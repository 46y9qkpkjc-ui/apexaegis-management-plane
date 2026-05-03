package security

import (
	"testing"

	"go.uber.org/zap"
)

func TestCreateTokenAndEnrollAgent(t *testing.T) {
	svc := NewEnrollmentService(zap.NewNop())

	tok, err := svc.CreateToken(CreateTokenRequest{
		Label:     "IT Department Laptops",
		GroupID:   "grp-it",
		GroupName: "IT",
		MaxUses:   3,
		TTLHours:  48,
	}, "admin@apexaegis.io")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if tok.Token == "" {
		t.Fatal("token string should not be empty")
	}
	if len(tok.Token) != 64 { // 32 bytes = 64 hex chars
		t.Fatalf("token should be 64 hex chars, got %d", len(tok.Token))
	}
	if tok.MaxUses != 3 {
		t.Fatalf("expected MaxUses=3, got %d", tok.MaxUses)
	}

	// Enroll an agent
	agent, err := svc.EnrollAgent(EnrollAgentRequest{
		Token:      tok.Token,
		DeviceName: "laptop-alpha",
		DeviceOS:   "windows",
		DeviceArch: "amd64",
	})
	if err != nil {
		t.Fatalf("EnrollAgent: %v", err)
	}
	if agent.AgentSecret == "" {
		t.Fatal("agent secret should be provided on enrollment")
	}
	if agent.GroupID != "grp-it" {
		t.Fatalf("agent should inherit group from token: got %q", agent.GroupID)
	}
	if !agent.Active {
		t.Fatal("agent should be active after enrollment")
	}
}

func TestEnrollAgentInvalidToken(t *testing.T) {
	svc := NewEnrollmentService(zap.NewNop())
	_, err := svc.EnrollAgent(EnrollAgentRequest{
		Token:      "nonexistent-token",
		DeviceName: "rogue-device",
		DeviceOS:   "linux",
	})
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestEnrollAgentRevokedToken(t *testing.T) {
	svc := NewEnrollmentService(zap.NewNop())
	tok, _ := svc.CreateToken(CreateTokenRequest{
		Label:   "revoke-test",
		GroupID: "grp-1",
	}, "admin")

	// Revoke the token
	if err := svc.RevokeToken(tok.ID); err != nil {
		t.Fatal(err)
	}

	// Try to enroll — should fail
	_, err := svc.EnrollAgent(EnrollAgentRequest{
		Token:      tok.Token,
		DeviceName: "should-fail",
		DeviceOS:   "linux",
	})
	if err == nil {
		t.Fatal("should reject enrollment with revoked token")
	}
}

func TestEnrollAgentMaxUsesExhausted(t *testing.T) {
	svc := NewEnrollmentService(zap.NewNop())
	tok, _ := svc.CreateToken(CreateTokenRequest{
		Label:   "single-use",
		GroupID: "grp-1",
		MaxUses: 1,
	}, "admin")

	// First enrollment should succeed
	_, err := svc.EnrollAgent(EnrollAgentRequest{
		Token:      tok.Token,
		DeviceName: "device-1",
		DeviceOS:   "windows",
	})
	if err != nil {
		t.Fatalf("first enrollment should succeed: %v", err)
	}

	// Second enrollment should fail
	_, err = svc.EnrollAgent(EnrollAgentRequest{
		Token:      tok.Token,
		DeviceName: "device-2",
		DeviceOS:   "linux",
	})
	if err == nil {
		t.Fatal("should reject when max uses exhausted")
	}
}

func TestDefaultMaxUsesAndTTL(t *testing.T) {
	svc := NewEnrollmentService(zap.NewNop())
	tok, _ := svc.CreateToken(CreateTokenRequest{
		Label:   "default-test",
		GroupID: "grp-1",
	}, "admin")

	if tok.MaxUses != 1 {
		t.Fatalf("default MaxUses should be 1, got %d", tok.MaxUses)
	}
	// Default TTL is 24 hours
	ttl := tok.ExpiresAt.Sub(tok.CreatedAt)
	if ttl < 23*3600*1e9 || ttl > 25*3600*1e9 {
		t.Fatalf("expected ~24h TTL, got %v", ttl)
	}
}

func TestListTokens(t *testing.T) {
	svc := NewEnrollmentService(zap.NewNop())
	svc.CreateToken(CreateTokenRequest{Label: "a", GroupID: "g1"}, "u")
	svc.CreateToken(CreateTokenRequest{Label: "b", GroupID: "g2"}, "u")

	tokens := svc.ListTokens()
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokens))
	}
}

func TestRevokeTokenNotFound(t *testing.T) {
	svc := NewEnrollmentService(zap.NewNop())
	if err := svc.RevokeToken("etk-nonexistent"); err == nil {
		t.Fatal("expected error for nonexistent token")
	}
}

func TestListAgentsRedactsSecret(t *testing.T) {
	svc := NewEnrollmentService(zap.NewNop())
	tok, _ := svc.CreateToken(CreateTokenRequest{Label: "test", GroupID: "g1", MaxUses: 5}, "admin")

	_, err := svc.EnrollAgent(EnrollAgentRequest{
		Token:      tok.Token,
		DeviceName: "secure-laptop",
		DeviceOS:   "macos",
		DeviceArch: "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}

	agents := svc.ListAgents()
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	if agents[0].AgentSecret != "" {
		t.Fatal("ListAgents should redact agent secret")
	}
	if agents[0].DeviceName != "secure-laptop" {
		t.Fatalf("agent name mismatch: %s", agents[0].DeviceName)
	}
}

func TestDeactivateAgent(t *testing.T) {
	svc := NewEnrollmentService(zap.NewNop())
	tok, _ := svc.CreateToken(CreateTokenRequest{Label: "test", GroupID: "g1", MaxUses: 5}, "admin")
	agent, _ := svc.EnrollAgent(EnrollAgentRequest{
		Token:      tok.Token,
		DeviceName: "to-deactivate",
		DeviceOS:   "windows",
	})

	if err := svc.DeactivateAgent(agent.ID); err != nil {
		t.Fatalf("DeactivateAgent: %v", err)
	}

	agents := svc.ListAgents()
	for _, a := range agents {
		if a.ID == agent.ID && a.Active {
			t.Fatal("agent should be inactive after deactivation")
		}
	}
}

func TestDeactivateAgentNotFound(t *testing.T) {
	svc := NewEnrollmentService(zap.NewNop())
	if err := svc.DeactivateAgent("agt-ghost"); err == nil {
		t.Fatal("expected error for nonexistent agent")
	}
}

func TestMultiUseToken(t *testing.T) {
	svc := NewEnrollmentService(zap.NewNop())
	tok, _ := svc.CreateToken(CreateTokenRequest{
		Label:   "multi-use",
		GroupID: "grp-fleet",
		MaxUses: 3,
	}, "admin")

	for i := 0; i < 3; i++ {
		_, err := svc.EnrollAgent(EnrollAgentRequest{
			Token:      tok.Token,
			DeviceName: "device-" + string(rune('A'+i)),
			DeviceOS:   "linux",
		})
		if err != nil {
			t.Fatalf("enrollment %d should succeed: %v", i+1, err)
		}
	}

	// 4th should fail
	_, err := svc.EnrollAgent(EnrollAgentRequest{
		Token:      tok.Token,
		DeviceName: "device-D",
		DeviceOS:   "linux",
	})
	if err == nil {
		t.Fatal("4th enrollment should fail on 3-use token")
	}
}
