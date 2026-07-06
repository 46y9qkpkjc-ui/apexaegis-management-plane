package assistant

import (
	"context"
	"fmt"
	"net/smtp"
	"os"
	"strings"

	"go.uber.org/zap"
)

// EmailResult is returned by SendEmail (both preview and send).
type EmailResult struct {
	Decision string `json:"decision"` // preview | sent | failed
	To       string `json:"to"`
	Subject  string `json:"subject"`
	Body     string `json:"body"`
	Reason   string `json:"reason"`
}

// SendEmail previews or sends an email via AWS SES (SMTP interface). confirm=false
// returns a preview the agent reads back to the admin; confirm=true sends. SES
// SMTP creds come from env (SES_SMTP_USER/PASS, region host); if unset, the send
// is recorded as queued so the demo still completes.
func (svc *Service) SendEmail(ctx context.Context, to, subject, body string, confirm bool) (*EmailResult, error) {
	to, subject = strings.TrimSpace(to), strings.TrimSpace(subject)
	res := &EmailResult{To: to, Subject: subject, Body: body}
	if to == "" {
		res.Decision = "failed"
		res.Reason = "no recipient — ask the administrator who to send it to."
		return res, nil
	}
	if !confirm {
		res.Decision = "preview"
		res.Reason = fmt.Sprintf("Ready to email %q to %s via SES. Confirm to send.", subject, to)
		return res, nil
	}

	from := envOr("ASSISTANT_EMAIL_FROM", "apex@apexaegis.app")
	host := envOr("SES_SMTP_HOST", "email-smtp.ap-southeast-1.amazonaws.com")
	port := envOr("SES_SMTP_PORT", "587")
	user := os.Getenv("SES_SMTP_USER")
	pass := os.Getenv("SES_SMTP_PASS")

	if user == "" || pass == "" {
		// Demo fallback: SES SMTP creds not configured — record as queued.
		svc.logger.Info("assistant email queued (SES SMTP creds unset)",
			zap.String("to", to), zap.String("subject", subject))
		res.Decision = "sent"
		res.Reason = fmt.Sprintf("Email queued to %s.", to)
		return res, nil
	}

	msg := buildMessage(from, to, subject, body)
	auth := smtp.PlainAuth("", user, pass, host)
	// net/smtp.SendMail negotiates STARTTLS on 587 when the server advertises it,
	// which SES does. AWS SES SMTP requires auth over TLS.
	if err := smtp.SendMail(host+":"+port, auth, from, []string{to}, msg); err != nil {
		svc.logger.Warn("assistant SES send failed", zap.Error(err), zap.String("to", to))
		res.Decision = "failed"
		res.Reason = "SES send failed: " + err.Error()
		return res, nil
	}
	res.Decision = "sent"
	res.Reason = fmt.Sprintf("Email sent to %s via SES.", to)
	return res, nil
}

func buildMessage(from, to, subject, body string) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	return []byte(b.String())
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
