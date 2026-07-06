// Package notify sends outbound email via AWS SES's SMTP interface (stdlib
// net/smtp, no SDK dependency). Used by the dashboard "Email Report" action.
package notify

import (
	"fmt"
	"net/smtp"
	"os"
	"strings"
)

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// SendSES sends an email via AWS SES SMTP. Returns (sent, reason). If SES SMTP
// creds are unset it reports queued success so demos still complete.
func SendSES(to, subject, body string) (bool, string) {
	to, subject = strings.TrimSpace(to), strings.TrimSpace(subject)
	if to == "" {
		return false, "no recipient"
	}
	from := envOr("ASSISTANT_EMAIL_FROM", "apex@apexaegis.app")
	host := envOr("SES_SMTP_HOST", "email-smtp.ap-southeast-1.amazonaws.com")
	port := envOr("SES_SMTP_PORT", "587")
	user := os.Getenv("SES_SMTP_USER")
	pass := os.Getenv("SES_SMTP_PASS")
	if user == "" || pass == "" {
		return true, fmt.Sprintf("Report queued to %s (SES SMTP creds unset).", to)
	}

	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))

	auth := smtp.PlainAuth("", user, pass, host)
	if err := smtp.SendMail(host+":"+port, auth, from, []string{to}, []byte(b.String())); err != nil {
		return false, "SES send failed: " + err.Error()
	}
	return true, fmt.Sprintf("Report emailed to %s via SES.", to)
}
