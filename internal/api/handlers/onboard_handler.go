package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zcp/management-plane/internal/db"
	"github.com/zcp/management-plane/internal/notify"
	"go.uber.org/zap"
)

// sesConfigured reports whether SES SMTP credentials are present. When they are
// not (demo/unconfigured environments), RequestOTP returns the code in the
// response so the storefront can display it — and automatically switches to
// email-only delivery the moment the creds are set, with no code change.
func sesConfigured() bool {
	return os.Getenv("SES_SMTP_USER") != "" && os.Getenv("SES_SMTP_PASS") != ""
}

// OnboardHandler serves the public client self-serve onboarding OTP flow.
// No JWT: access is gated by a one-time passcode emailed to the address the
// client registered with sales/an account manager. Codes are valid 4 hours.
type OnboardHandler struct {
	db     *db.DB
	logger *zap.Logger
}

func NewOnboardHandler(database *db.DB, logger *zap.Logger) *OnboardHandler {
	return &OnboardHandler{db: database, logger: logger}
}

const onboardOTPTTL = 4 * time.Hour
const maxOTPAttempts = 5

var onboardEmailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randomDigits(n int) string {
	const digits = "0123456789"
	b := make([]byte, n)
	for i := range b {
		idx, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			b[i] = '0'
			continue
		}
		b[i] = digits[idx.Int64()]
	}
	return string(b)
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return sha256Hex(time.Now().String())
	}
	return hex.EncodeToString(b)
}

// RequestOTP handles POST /api/v1/onboard/otp/request.
// Always returns 200 on a well-formed email so we don't reveal who has been invited.
func (h *OnboardHandler) RequestOTP(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !onboardEmailRe.MatchString(email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid email"})
		return
	}

	ctx := c.Request.Context()
	code := randomDigits(6)
	if _, err := h.db.ExecContext(ctx,
		`INSERT INTO onboard_otps (email, code_hash, expires_at) VALUES ($1, $2, $3)`,
		email, sha256Hex(code), time.Now().Add(onboardOTPTTL),
	); err != nil {
		h.logger.Error("onboard otp insert failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not issue passcode"})
		return
	}

	// No SES creds → demo mode: return the code so the storefront can show it.
	if !sesConfigured() {
		h.logger.Warn("onboard otp: SES not configured, returning code in response (demo mode)",
			zap.String("email", email))
		c.JSON(http.StatusOK, gin.H{"ok": true, "demo": true, "code": code})
		return
	}

	subject := "Your ApexAegis onboarding passcode"
	body := "Your ApexAegis one-time passcode is:\n\n    " + code + "\n\n" +
		"Enter it on the onboarding page to continue. It is valid for 4 hours.\n" +
		"If you didn't request this, you can safely ignore this email.\n\n— ApexAegis"
	sent, reason := notify.SendSES(email, subject, body)
	h.logger.Info("onboard otp requested",
		zap.String("email", email), zap.Bool("sent", sent), zap.String("reason", reason))

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// VerifyOTP handles POST /api/v1/onboard/otp/verify.
func (h *OnboardHandler) VerifyOTP(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	code := strings.TrimSpace(req.Code)
	if !onboardEmailRe.MatchString(email) || len(code) != 6 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	ctx := c.Request.Context()
	var id, codeHash string
	err := h.db.QueryRowContext(ctx,
		`SELECT id, code_hash FROM onboard_otps
		   WHERE email = $1 AND consumed_at IS NULL AND expires_at > now() AND attempts < $2
		   ORDER BY created_at DESC LIMIT 1`,
		email, maxOTPAttempts,
	).Scan(&id, &codeHash)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired passcode"})
		return
	}

	if sha256Hex(code) != codeHash {
		_, _ = h.db.ExecContext(ctx, `UPDATE onboard_otps SET attempts = attempts + 1 WHERE id = $1`, id)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired passcode"})
		return
	}

	token := randomToken()
	expiresAt := time.Now().Add(onboardOTPTTL)
	if _, err := h.db.ExecContext(ctx,
		`UPDATE onboard_otps SET consumed_at = now(), token = $1 WHERE id = $2`, token, id,
	); err != nil {
		h.logger.Error("onboard otp consume failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not complete verification"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":      token,
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
	})
}
