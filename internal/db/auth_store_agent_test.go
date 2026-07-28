package db

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

func TestIssueAgentTokenBindsDeviceCertificate(t *testing.T) {
	secret := []byte("test-secret")
	store := NewAuthStore(nil, secret, zap.NewNop())

	tokenString, _, err := store.IssueAgentToken("tenant-1", "device-1", "aabbcc", "1234", []string{"IT Team"},
		AgentTokenDomain{DomainJoined: true, UPN: "mark@ad.apexaegis.app"},
		AgentTokenPosture{Compliant: true, Status: "compliant"},
		"ad\\mark.console")
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
	groups, ok := claims["groups"].([]interface{})
	if !ok || len(groups) != 1 || groups[0] != "IT Team" {
		t.Fatalf("expected groups claim [IT Team], got %v", claims["groups"])
	}
	if dj, _ := claims["domain_joined"].(bool); !dj {
		t.Fatalf("expected domain_joined=true claim, got %v", claims["domain_joined"])
	}
	if claims["upn"] != "mark@ad.apexaegis.app" {
		t.Fatalf("unexpected upn claim: %v", claims["upn"])
	}
	if claims["user_id"] != "ad\\mark.console" {
		t.Fatalf("expected user_id claim from login_user, got %v", claims["user_id"])
	}
}

func TestIssueAgentTokenRequiresDeviceCertificate(t *testing.T) {
	store := NewAuthStore(nil, []byte("test-secret"), zap.NewNop())

	if _, _, err := store.IssueAgentToken("tenant-1", "device-1", "", "", nil, AgentTokenDomain{}, AgentTokenPosture{}, ""); err == nil {
		t.Fatal("expected missing device certificate identity to be rejected")
	}
}
