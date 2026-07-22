package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// ITSMTicket is one internal ITSM ticket (service/change request or incident).
type ITSMTicket struct {
	ID             string `json:"id"`
	OrgID          string `json:"org_id"`
	TenantName     string `json:"tenant_name,omitempty"`
	Operator       string `json:"operator,omitempty"`
	TicketKey      string `json:"ticket_key"`
	Provider       string `json:"provider"`    // internal | jira | servicenow
	TicketType     string `json:"ticket_type"` // service_request | change_request | incident
	Status         string `json:"status"`
	Priority       string `json:"priority"`
	Summary        string `json:"summary"`
	Description    string `json:"description"`
	Requester      string `json:"requester"`
	Assignee       string `json:"assignee"`
	ExternalRef    string `json:"external_ref,omitempty"`
	RiskDecisionID string `json:"risk_decision_id,omitempty"`
	CreatedAt      string `json:"created_at,omitempty"`
	UpdatedAt      string `json:"updated_at,omitempty"`
}

// ITSMStore persists internal ITSM tickets. Tenant-scoped (org_id); operator
// visibility is derived on read by joining organizations.operator.
type ITSMStore struct {
	db     *DB
	logger *zap.Logger
}

func NewITSMStore(db *DB, logger *zap.Logger) *ITSMStore {
	return &ITSMStore{db: db, logger: logger}
}

// typePrefix maps a ticket type to its human key prefix.
func typePrefix(t string) string {
	switch t {
	case "service_request":
		return "SR"
	case "change_request":
		return "CR"
	default:
		return "INC"
	}
}

// Create inserts a ticket, generating a human ticket_key (e.g. SR-7F3K9Q).
func (s *ITSMStore) Create(ctx context.Context, orgID string, t ITSMTicket) (*ITSMTicket, error) {
	if t.Provider == "" {
		t.Provider = "internal"
	}
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	t.TicketKey = fmt.Sprintf("%s-%s", typePrefix(t.TicketType), strings.ToUpper(hex.EncodeToString(b)))
	var riskID interface{}
	if t.RiskDecisionID != "" {
		riskID = t.RiskDecisionID
	}
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO system_mgmt.itsm_tickets
		  (org_id, ticket_key, provider, ticket_type, status, priority, summary,
		   description, requester, assignee, external_ref, risk_decision_id)
		VALUES ($1,$2,$3,$4, COALESCE(NULLIF($5,''),'open'), COALESCE(NULLIF($6,''),'medium'),
		        $7,$8,$9,$10,$11,$12)
		RETURNING id, ticket_key, status, priority, created_at::text`,
		orgID, t.TicketKey, t.Provider, t.TicketType, t.Status, t.Priority, t.Summary,
		t.Description, t.Requester, t.Assignee, t.ExternalRef, riskID).
		Scan(&t.ID, &t.TicketKey, &t.Status, &t.Priority, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	t.OrgID = orgID
	return &t, nil
}

// List returns tickets visible to the caller's scope (operator fleet / own org /
// all), newest first.
func (s *ITSMStore) List(ctx context.Context, scope TenantScope, limit int) ([]ITSMTicket, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	q := `SELECT t.id, t.org_id, o.name, COALESCE(o.operator,'ApexAegis (direct)'), t.ticket_key,
	             t.provider, t.ticket_type, t.status, t.priority, t.summary, t.description,
	             t.requester, t.assignee, t.external_ref, COALESCE(t.risk_decision_id::text,''),
	             t.created_at::text, t.updated_at::text
	      FROM system_mgmt.itsm_tickets t
	      JOIN system_mgmt.organizations o ON o.id = t.org_id
	      WHERE 1=1`
	args := []interface{}{}
	if scope.Operator != "" {
		args = append(args, scope.Operator)
		q += fmt.Sprintf(" AND COALESCE(o.operator,'ApexAegis (direct)') = $%d", len(args))
	} else if scope.OrgID != "" {
		args = append(args, scope.OrgID)
		q += fmt.Sprintf(" AND t.org_id = $%d", len(args))
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY t.created_at DESC LIMIT $%d", len(args))
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ITSMTicket{}
	for rows.Next() {
		var t ITSMTicket
		if err := rows.Scan(&t.ID, &t.OrgID, &t.TenantName, &t.Operator, &t.TicketKey,
			&t.Provider, &t.TicketType, &t.Status, &t.Priority, &t.Summary, &t.Description,
			&t.Requester, &t.Assignee, &t.ExternalRef, &t.RiskDecisionID, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// UpdateStatus transitions a ticket (tenant-guarded).
func (s *ITSMStore) UpdateStatus(ctx context.Context, orgID, id, status string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE system_mgmt.itsm_tickets SET status=$3, updated_at=now()
		WHERE id=$1 AND org_id=$2`, id, orgID, status)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
