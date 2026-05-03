// Package middleware provides HTTP middleware for the management plane API.
package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// SafeRecovery replaces Gin's default recovery middleware. It catches panics and
// returns a sanitised error response — never exposing Go stack traces to clients.
func SafeRecovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				reqID := c.GetString("request_id")
				if reqID == "" {
					reqID = generateShortID()
				}

				// Log the real error server-side (structured, never sent to client)
				fmt.Printf("[PANIC] request_id=%s recovered: %v\n", reqID, r)

				if wantsHTML(c) {
					c.Data(http.StatusInternalServerError, "text/html; charset=utf-8",
						renderErrorHTML(http.StatusInternalServerError, "Internal Server Error",
							"An unexpected error occurred. Please try again later.", reqID))
				} else {
					c.JSON(http.StatusInternalServerError, gin.H{
						"error":      "Internal server error",
						"request_id": reqID,
					})
				}
				c.Abort()
			}
		}()
		c.Next()
	}
}

// ErrorHandler is a middleware that wraps Gin handler errors into safe responses.
// Handlers should use c.Error(err) to register errors, then this middleware
// translates them into user-safe messages.
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) == 0 {
			return
		}

		reqID := c.GetString("request_id")
		status := c.Writer.Status()
		if status == http.StatusOK {
			status = http.StatusInternalServerError
		}

		msg := SafeMessage(status)

		if wantsHTML(c) {
			c.Data(status, "text/html; charset=utf-8",
				renderErrorHTML(status, http.StatusText(status), msg, reqID))
		} else {
			c.JSON(status, gin.H{
				"error":      msg,
				"request_id": reqID,
			})
		}
	}
}

// AbortWithSafeError stops the request and returns a sanitised error.
// Use this in handlers instead of exposing raw error messages.
func AbortWithSafeError(c *gin.Context, status int, internalErr error) {
	reqID := c.GetString("request_id")

	// Log the real error server-side
	if internalErr != nil {
		fmt.Printf("[ERROR] request_id=%s status=%d err=%v\n", reqID, status, internalErr)
	}

	msg := SafeMessage(status)

	if wantsHTML(c) {
		c.Data(status, "text/html; charset=utf-8",
			renderErrorHTML(status, http.StatusText(status), msg, reqID))
	} else {
		c.JSON(status, gin.H{
			"error":      msg,
			"request_id": reqID,
		})
	}
	c.Abort()
}

// SafeMessage maps HTTP status codes to user-friendly messages.
func SafeMessage(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "The request was invalid. Please check your input and try again."
	case http.StatusUnauthorized:
		return "Authentication required. Please provide valid credentials."
	case http.StatusForbidden:
		return "You do not have permission to perform this action."
	case http.StatusNotFound:
		return "The requested resource was not found."
	case http.StatusConflict:
		return "The request conflicts with the current state of the resource."
	case http.StatusTooManyRequests:
		return "Too many requests. Please try again later."
	case http.StatusServiceUnavailable:
		return "The service is temporarily unavailable. Please try again later."
	default:
		return "An unexpected error occurred. Please try again later."
	}
}

// wantsHTML checks if the client prefers HTML responses (browser vs. API client).
func wantsHTML(c *gin.Context) bool {
	accept := c.GetHeader("Accept")
	return strings.Contains(accept, "text/html")
}

// renderErrorHTML returns a styled HTML error page.
func renderErrorHTML(status int, title, message, requestID string) []byte {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%d — %s | ApexAegis</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
     background:#0a0a0f;color:#e2e8f0;display:flex;align-items:center;
     justify-content:center;min-height:100vh;padding:2rem}
.card{max-width:480px;width:100%%;text-align:center;background:#111827;
      border:1px solid #1f2937;border-radius:16px;padding:3rem 2rem}
.code{font-size:4rem;font-weight:800;background:linear-gradient(135deg,#3b82f6,#6366f1);
      -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:.5rem}
.title{font-size:1.25rem;font-weight:600;color:#f1f5f9;margin-bottom:1rem}
.msg{font-size:.875rem;color:#94a3b8;line-height:1.6;margin-bottom:1.5rem}
.rid{font-size:.75rem;color:#475569;font-family:monospace}
.home{display:inline-block;margin-top:1.5rem;padding:.625rem 1.5rem;
      background:#3b82f6;color:#fff;border-radius:8px;text-decoration:none;
      font-size:.875rem;font-weight:500;transition:background .2s}
.home:hover{background:#2563eb}
.logo{width:48px;height:48px;background:linear-gradient(135deg,#3b82f6,#1d4ed8);
      border-radius:12px;margin:0 auto 1.5rem;display:flex;align-items:center;
      justify-content:center;font-weight:700;font-size:1.25rem;color:#fff}
</style>
</head>
<body>
<div class="card">
  <div class="logo">A</div>
  <div class="code">%d</div>
  <div class="title">%s</div>
  <div class="msg">%s</div>
  <div class="rid">Request ID: %s</div>
  <a href="/" class="home">Go Home</a>
</div>
</body>
</html>`, status, title, status, title, message, requestID)
	return []byte(html)
}

func generateShortID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
