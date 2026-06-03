package db

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

func TestIssueAgentTokenBindsDeviceCertificate(t *testing.T) {
	secret := []byte("test-secret")
	store := NewAuthStore(nil, secret, zap.NewNop())

	tokenString, _, err := store.IssueAgentToken("tenant-1", "device-1", "aabbcc", "1234")
	if err != nil {
		t.Fatalf("IssueAgentToken failed: %v", err)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil || !token.Valid {
		t.Fatalf("issued token is invalid: %v", err)
	}

	claims := token.Claims.(jwt.MapClaims)
	if claims["device_cert_fingerprint_sha256"] != "aabbcc" {
		t.Fatalf("unexpected fingerprint claim: %v", claims["device_cert_fingerprint_sha256"])
	}
	if claims["device_cert_serial"] != "1234" {
		t.Fatalf("unexpected serial claim: %v", claims["device_cert_serial"])
	}
}

func TestIssueAgentTokenRequiresDeviceCertificate(t *testing.T) {
	store := NewAuthStore(nil, []byte("test-secret"), zap.NewNop())

	if _, _, err := store.IssueAgentToken("tenant-1", "device-1", "", ""); err == nil {
		t.Fatal("expected missing device certificate identity to be rejected")
	}
}
