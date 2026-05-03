// Package scanner — ApexAdversary outreach engine.
// For every non-compliant TLS endpoint discovered by the scanner,
// creates a business opportunity on apexadversary.com and sends
// an email to the application service provider with a remediation
// report and a proposal for ApexAegis to fix it.
package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Opportunity represents a business lead created from a non-compliant scan.
type Opportunity struct {
	ID             string          `json:"id"`
	Host           string          `json:"host"`
	Compliance     ComplianceLevel `json:"compliance"`
	Findings       []Finding       `json:"findings"`
	URLCategory    URLCategory     `json:"url_category"`
	ContactEmail   string          `json:"contact_email,omitempty"`
	ServiceName    string          `json:"service_name"`
	Status         string          `json:"status"` // new, email_sent, responded, fixed, closed
	CreatedAt      time.Time       `json:"created_at"`
	EmailSentAt    *time.Time      `json:"email_sent_at,omitempty"`
	ProposalType   string          `json:"proposal_type"` // self_fix, managed_fix
	ScanResultID   string          `json:"scan_result_id"`
	OrgID          string          `json:"org_id"`
}

// OutreachConfig holds the outreach engine configuration.
type OutreachConfig struct {
	ApexAdversaryAPI string // https://api.apexadversary.com
	APIKey           string
	SMTPEndpoint     string // SMTP relay or email API endpoint
	FromEmail        string
	FromName         string
	Enabled          bool
}

// OutreachEngine manages the lifecycle of TLS compliance opportunities.
type OutreachEngine struct {
	mu            sync.RWMutex
	opportunities map[string]*Opportunity // opportunity_id -> opportunity
	config        OutreachConfig
	logger        *zap.Logger
	httpClient    *http.Client
}

// NewOutreachEngine creates the ApexAdversary outreach engine.
func NewOutreachEngine(cfg OutreachConfig, logger *zap.Logger) *OutreachEngine {
	return &OutreachEngine{
		opportunities: make(map[string]*Opportunity),
		config:        cfg,
		logger:        logger,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// ProcessNonCompliant takes scan results, creates opportunities, and sends emails.
func (e *OutreachEngine) ProcessNonCompliant(ctx context.Context, results []ScanResult) []Opportunity {
	var created []Opportunity

	for _, r := range results {
		if r.Compliance != NonCompliant && r.Compliance != Critical {
			continue
		}

		opp := Opportunity{
			ID:           fmt.Sprintf("opp-%s-%d", r.Host, time.Now().UnixMilli()),
			Host:         r.Host,
			Compliance:   r.Compliance,
			Findings:     r.Findings,
			URLCategory:  r.URLCategory,
			ServiceName:  deriveServiceName(r.Host),
			Status:       "new",
			CreatedAt:    time.Now().UTC(),
			ProposalType: proposalType(r.Compliance),
			ScanResultID: r.ID,
			OrgID:        r.OrgID,
		}

		// Derive contact email from domain (abuse@ or security@)
		opp.ContactEmail = deriveContactEmail(r.Host)

		// Create opportunity in ApexAdversary platform
		if e.config.Enabled {
			if err := e.createOpportunity(ctx, &opp); err != nil {
				e.logger.Warn("Failed to create opportunity in ApexAdversary",
					zap.String("host", r.Host),
					zap.Error(err),
				)
			}
		}

		e.mu.Lock()
		e.opportunities[opp.ID] = &opp
		e.mu.Unlock()

		created = append(created, opp)
	}

	return created
}

// SendOutreachEmails sends remediation emails for new opportunities.
func (e *OutreachEngine) SendOutreachEmails(ctx context.Context) (sent int, errs int) {
	e.mu.RLock()
	var pending []*Opportunity
	for _, opp := range e.opportunities {
		if opp.Status == "new" && opp.ContactEmail != "" {
			pending = append(pending, opp)
		}
	}
	e.mu.RUnlock()

	for _, opp := range pending {
		if err := e.sendRemediationEmail(ctx, opp); err != nil {
			e.logger.Warn("Failed to send outreach email",
				zap.String("host", opp.Host),
				zap.String("email", opp.ContactEmail),
				zap.Error(err),
			)
			errs++
			continue
		}

		e.mu.Lock()
		now := time.Now().UTC()
		opp.EmailSentAt = &now
		opp.Status = "email_sent"
		e.mu.Unlock()

		sent++
		e.logger.Info("Outreach email sent",
			zap.String("host", opp.Host),
			zap.String("to", opp.ContactEmail),
			zap.String("proposal", opp.ProposalType),
		)
	}
	return
}

// ListOpportunities returns all tracked opportunities.
func (e *OutreachEngine) ListOpportunities() []Opportunity {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Opportunity, 0, len(e.opportunities))
	for _, opp := range e.opportunities {
		out = append(out, *opp)
	}
	return out
}

// GetOpportunity returns a single opportunity by ID.
func (e *OutreachEngine) GetOpportunity(id string) (*Opportunity, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	opp, ok := e.opportunities[id]
	if !ok {
		return nil, false
	}
	cp := *opp
	return &cp, true
}

// UpdateStatus updates the status of an opportunity.
func (e *OutreachEngine) UpdateStatus(id, status string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	opp, ok := e.opportunities[id]
	if !ok {
		return false
	}
	opp.Status = status
	return true
}

// ── ApexAdversary API ──────────────────────────────────────────────

func (e *OutreachEngine) createOpportunity(ctx context.Context, opp *Opportunity) error {
	payload, err := json.Marshal(map[string]interface{}{
		"host":          opp.Host,
		"service_name":  opp.ServiceName,
		"compliance":    opp.Compliance,
		"url_category":  opp.URLCategory,
		"findings":      opp.Findings,
		"contact_email": opp.ContactEmail,
		"proposal_type": opp.ProposalType,
		"source":        "apexaegis-scanner",
	})
	if err != nil {
		return fmt.Errorf("marshal opportunity: %w", err)
	}

	apiURL := e.config.ApexAdversaryAPI + "/api/v1/opportunities"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", e.config.APIKey)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("api call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("api returned status %d", resp.StatusCode)
	}

	e.logger.Info("Opportunity created in ApexAdversary",
		zap.String("host", opp.Host),
		zap.String("id", opp.ID),
	)
	return nil
}

// ── Email ──────────────────────────────────────────────────────────

func (e *OutreachEngine) sendRemediationEmail(ctx context.Context, opp *Opportunity) error {
	body, err := renderEmail(opp)
	if err != nil {
		return fmt.Errorf("render email: %w", err)
	}

	payload, err := json.Marshal(map[string]interface{}{
		"from":     fmt.Sprintf("%s <%s>", e.config.FromName, e.config.FromEmail),
		"to":       opp.ContactEmail,
		"subject":  fmt.Sprintf("TLS Compliance Alert — %s", opp.Host),
		"html":     body,
		"category": "tls-compliance-outreach",
		"metadata": map[string]string{
			"opportunity_id": opp.ID,
			"host":           opp.Host,
		},
	})
	if err != nil {
		return fmt.Errorf("marshal email: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.config.SMTPEndpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create email request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", e.config.APIKey)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send email: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("email API returned status %d", resp.StatusCode)
	}
	return nil
}

func renderEmail(opp *Opportunity) (string, error) {
	tmpl := template.Must(template.New("email").Parse(emailTemplate))
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, opp); err != nil {
		return "", err
	}
	return buf.String(), nil
}

const emailTemplate = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: #1a1a2e; max-width: 640px; margin: 0 auto; padding: 20px; }
.header { background: linear-gradient(135deg, #1a56db, #7c3aed); padding: 24px; border-radius: 12px; color: white; margin-bottom: 24px; }
.header h1 { margin: 0; font-size: 20px; }
.header p { margin: 8px 0 0; opacity: 0.9; font-size: 14px; }
.finding { background: #fef2f2; border-left: 4px solid #ef4444; padding: 12px 16px; margin: 8px 0; border-radius: 0 8px 8px 0; }
.finding.high { background: #fff7ed; border-color: #f97316; }
.finding.medium { background: #fefce8; border-color: #eab308; }
.finding .label { font-weight: 600; font-size: 12px; text-transform: uppercase; }
.cta { display: inline-block; background: #1a56db; color: white; padding: 12px 28px; border-radius: 8px; text-decoration: none; font-weight: 600; margin: 16px 0; }
.footer { margin-top: 32px; padding-top: 16px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #6b7280; }
</style></head>
<body>
<div class="header">
  <h1>TLS Compliance Report</h1>
  <p>{{.Host}} — Scanned by ApexAegis Security</p>
</div>

<p>Dear Security Team at <strong>{{.ServiceName}}</strong>,</p>

<p>Our automated TLS compliance scanner has detected the following issues
with <strong>{{.Host}}</strong>:</p>

{{range .Findings}}
<div class="finding {{.Severity}}">
  <div class="label">{{.Severity}} — {{.Code}}</div>
  <p style="margin:4px 0 0">{{.Description}}</p>
</div>
{{end}}

<p>These findings may affect your users' security and trust. We recommend
addressing them promptly.</p>

<h3>How we can help</h3>
{{if eq .ProposalType "self_fix"}}
<p>We've prepared a detailed remediation guide for your team. Most of these
issues can be resolved with updated TLS configuration.</p>
{{else}}
<p>Our team at <strong>ApexAegis</strong> can implement the necessary fixes
for you — including certificate renewal, TLS 1.3 upgrade, and HSTS
deployment.</p>
{{end}}

<a href="https://apexadversary.com/report/{{.ID}}" class="cta">View Full Report</a>

<div class="footer">
  <p>This report was generated by ApexAegis TLS Compliance Scanner.<br>
  If you believe this was sent in error, please contact us at security@apexadversary.com</p>
</div>
</body>
</html>`

// ── Helpers ─────────────────────────────────────────────────────────

func deriveServiceName(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		// Take the second-level domain and capitalize
		name := parts[len(parts)-2]
		if len(name) > 0 {
			return strings.ToUpper(name[:1]) + name[1:]
		}
	}
	return host
}

func deriveContactEmail(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		domain := strings.Join(parts[len(parts)-2:], ".")
		return "security@" + domain
	}
	return ""
}

func proposalType(c ComplianceLevel) string {
	if c == Critical {
		return "managed_fix"
	}
	return "self_fix"
}
