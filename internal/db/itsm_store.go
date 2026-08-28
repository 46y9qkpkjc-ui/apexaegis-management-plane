package db

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ITSMTicket represents an ITSM service request ticket.
type ITSMTicket struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	TicketKey       string     `json:"ticket_key"`
	Provider        string     `json:"provider"`
	TicketType      string     `json:"ticket_type"`
	Status          string     `json:"status"`
	Priority        string     `json:"priority"`
	Summary         string     `json:"summary"`
	Description     string     `json:"description,omitempty"`
	Requester       string     `json:"requester,omitempty"`
	Assignee        string     `json:"assignee,omitempty"`
	Domain          string     `json:"domain,omitempty"`
	Category        string     `json:"category,omitempty"`
	PolicyID        string     `json:"policy_id,omitempty"`
	DeviceID        string     `json:"device_id,omitempty"`
	UserID          string     `json:"user_id,omitempty"`
	Justification   string     `json:"justification,omitempty"`
	DurationHours   *int       `json:"duration_hours,omitempty"`
	ContactMethod   string     `json:"contact_method,omitempty"`
	AIDecision      string     `json:"ai_decision,omitempty"`
	AIScore         *int       `json:"ai_score,omitempty"`
	RBISessionURL   string     `json:"rbi_session_url,omitempty"`
	RBIExpiry       *time.Time `json:"rbi_expiry,omitempty"`
	RejectionReason string     `json:"rejection_reason,omitempty"`
	RiskDecisionID  string     `json:"risk_decision_id,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

const itsmTicketCols = `
	id, tenant_id, ticket_key, provider, ticket_type, status, priority,
	summary, COALESCE(description,''), COALESCE(requester,''), COALESCE(assignee,''),
	COALESCE(domain,''), COALESCE(category,''), COALESCE(policy_id,''),
	COALESCE(device_id,''), COALESCE(user_id,''), COALESCE(justification,''),
	duration_hours, COALESCE(contact_method,''), COALESCE(ai_decision,''),
	ai_score, COALESCE(rbi_session_url,''), rbi_expiry,
	COALESCE(rejection_reason,''), COALESCE(risk_decision_id,''),
	created_at, updated_at
`

// ITSMStore manages ITSM ticket persistence.
type ITSMStore struct {
	db     *DB
	logger *zap.Logger
}

// NewITSMStore creates a new ITSM store.
func NewITSMStore(db *DB, logger *zap.Logger) *ITSMStore {
	return &ITSMStore{db: db, logger: logger}
}

func scanITSMTicket(scan func(dest ...any) error) (*ITSMTicket, error) {
	t := &ITSMTicket{}
	err := scan(
		&t.ID, &t.TenantID, &t.TicketKey, &t.Provider, &t.TicketType,
		&t.Status, &t.Priority, &t.Summary, &t.Description, &t.Requester,
		&t.Assignee, &t.Domain, &t.Category, &t.PolicyID, &t.DeviceID,
		&t.UserID, &t.Justification, &t.DurationHours, &t.ContactMethod,
		&t.AIDecision, &t.AIScore, &t.RBISessionURL, &t.RBIExpiry,
		&t.RejectionReason, &t.RiskDecisionID, &t.CreatedAt, &t.UpdatedAt,
	)
	return t, err
}

// CreateTicket inserts a new ITSM ticket and returns the generated ticket_key.
func (s *ITSMStore) CreateTicket(ctx context.Context, t *ITSMTicket) (*ITSMTicket, error) {
	const prefix = "SR-"
	var ticketKey string

	// Generate a unique ticket key: SR-XXXXX (5-digit random)
	for {
		var exists bool
		err := s.db.DB.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM system_mgmt.itsm_tickets WHERE ticket_key = $1)`,
			t.TicketKey,
		).Scan(&exists)
		if err != nil {
			return nil, fmt.Errorf("check ticket_key: %w", err)
		}
		if !exists {
			ticketKey = t.TicketKey
			break
		}
		// Collision — regenerate
		t.TicketKey = fmt.Sprintf("%s%05d", prefix, time.Now().UnixNano()%100000)
	}
	t.TicketKey = ticketKey

	query := `INSERT INTO system_mgmt.itsm_tickets (
		tenant_id, ticket_key, provider, ticket_type, status, priority,
		summary, description, requester, assignee, domain, category,
		policy_id, device_id, user_id, justification, duration_hours,
		contact_method, ai_decision, ai_score, rbi_session_url, rbi_expiry,
		rejection_reason, risk_decision_id
	) VALUES (
		$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24
	) RETURNING ` + itsmTicketCols

	row := s.db.DB.QueryRowContext(ctx, query,
		t.TenantID, t.TicketKey, t.Provider, t.TicketType, t.Status, t.Priority,
		t.Summary, t.Description, t.Requester, t.Assignee, t.Domain, t.Category,
		t.PolicyID, t.DeviceID, t.UserID, t.Justification, t.DurationHours,
		t.ContactMethod, t.AIDecision, t.AIScore, t.RBISessionURL, t.RBIExpiry,
		t.RejectionReason, t.RiskDecisionID,
	)

	created, err := scanITSMTicket(row.Scan)
	if err != nil {
		return nil, fmt.Errorf("insert itsm ticket: %w", err)
	}
	return created, nil
}

// GetTicket retrieves a ticket by ID or ticket_key.
func (s *ITSMStore) GetTicket(ctx context.Context, tenantID, idOrKey string) (*ITSMTicket, error) {
	query := `SELECT ` + itsmTicketCols + ` FROM system_mgmt.itsm_tickets
		WHERE tenant_id = $1 AND (id::text = $2 OR ticket_key = $2)`
	row := s.db.DB.QueryRowContext(ctx, query, tenantID, idOrKey)
	t, err := scanITSMTicket(row.Scan)
	if err != nil {
		return nil, fmt.Errorf("get itsm ticket: %w", err)
	}
	return t, nil
}

// ListTickets returns all tickets for a tenant, optionally filtered by status.
func (s *ITSMStore) ListTickets(ctx context.Context, tenantID, status string, limit, offset int) ([]*ITSMTicket, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{tenantID}
	argN := 1

	if status != "" {
		argN++
		where = append(where, fmt.Sprintf("status = $%d", argN))
		args = append(args, status)
	}

	whereClause := strings.Join(where, " AND ")

	// Count total
	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM system_mgmt.itsm_tickets WHERE %s", whereClause)
	if err := s.db.DB.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count itsm tickets: %w", err)
	}

	// Fetch page
	if limit <= 0 {
		limit = 50
	}
	argN++
	whereClause += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", argN)
	args = append(args, limit)
	argN++
	whereClause += fmt.Sprintf(" OFFSET $%d", argN)
	args = append(args, offset)

	query := fmt.Sprintf("SELECT %s FROM system_mgmt.itsm_tickets WHERE %s", itsmTicketCols, whereClause)
	rows, err := s.db.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list itsm tickets: %w", err)
	}
	defer rows.Close()

	var tickets []*ITSMTicket
	for rows.Next() {
		t, err := scanITSMTicket(rows.Scan)
		if err != nil {
			return nil, 0, fmt.Errorf("scan itsm ticket: %w", err)
		}
		tickets = append(tickets, t)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows error: %w", err)
	}
	if tickets == nil {
		tickets = []*ITSMTicket{}
	}
	return tickets, total, nil
}

// UpdateTicket updates mutable fields of a ticket.
func (s *ITSMStore) UpdateTicket(ctx context.Context, tenantID, id string, updates map[string]any) (*ITSMTicket, error) {
	allowed := map[string]bool{
		"status": true, "assignee": true, "priority": true, "description": true,
		"ai_decision": true, "ai_score": true, "rbi_session_url": true,
		"rbi_expiry": true, "rejection_reason": true, "summary": true,
	}

	setClauses := []string{}
	args := []any{}
	argN := 0

	for k, v := range updates {
		if !allowed[k] {
			continue
		}
		argN++
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", k, argN))
		args = append(args, v)
	}

	if len(setClauses) == 0 {
		return s.GetTicket(ctx, tenantID, id)
	}

	argN++
	setClauses = append(setClauses, fmt.Sprintf("updated_at = $%d", argN))
	args = append(args, time.Now())

	argN++
	args = append(args, tenantID)
	argN++
	args = append(args, id)

	query := fmt.Sprintf(
		`UPDATE system_mgmt.itsm_tickets SET %s
		 WHERE tenant_id = $%d AND (id::text = $%d OR ticket_key = $%d)
		 RETURNING %s`,
		strings.Join(setClauses, ", "), argN-2, argN-1, argN, itsmTicketCols,
	)

	row := s.db.DB.QueryRowContext(ctx, query, args...)
	t, err := scanITSMTicket(row.Scan)
	if err != nil {
		return nil, fmt.Errorf("update itsm ticket: %w", err)
	}
	return t, nil
}

// DeleteTicket soft-deletes a ticket by setting status to 'expired'.
func (s *ITSMStore) DeleteTicket(ctx context.Context, tenantID, id string) error {
	query := `UPDATE system_mgmt.itsm_tickets SET status = 'expired', updated_at = now()
		WHERE tenant_id = $1 AND (id::text = $2 OR ticket_key = $2)`
	_, err := s.db.DB.ExecContext(ctx, query, tenantID, id)
	if err != nil {
		return fmt.Errorf("delete itsm ticket: %w", err)
	}
	return nil
}

// CountByStatus returns ticket counts grouped by status for a tenant.
func (s *ITSMStore) CountByStatus(ctx context.Context, tenantID string) (map[string]int, error) {
	query := `SELECT status, COUNT(*) FROM system_mgmt.itsm_tickets
		WHERE tenant_id = $1 GROUP BY status`
	rows, err := s.db.DB.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("count by status: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		counts[status] = count
	}
	return counts, rows.Err()
}
