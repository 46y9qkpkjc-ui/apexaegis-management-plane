package security

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"go.uber.org/zap"
)

func newTestCommandSigning(t *testing.T) (*CommandSigningService, *CodeSigningService) {
	t.Helper()
	codeSvc := NewCodeSigningService(zap.NewNop())
	cmdSvc := NewCommandSigningService(codeSvc, zap.NewNop())
	return cmdSvc, codeSvc
}

func TestIssueAndVerifyCommand(t *testing.T) {
	cmdSvc, _ := newTestCommandSigning(t)

	cmd, err := cmdSvc.IssueCommand(IssueCommandRequest{
		CommandType: "policy_push",
		TargetID:    "agt-001",
		Payload:     `{"policies":["block-malware"]}`,
	}, "admin@apexaegis.io")
	if err != nil {
		t.Fatalf("IssueCommand: %v", err)
	}

	if cmd.Nonce == "" {
		t.Fatal("nonce should not be empty")
	}
	if cmd.Signature == "" {
		t.Fatal("signature should not be empty")
	}

	// Verify the command
	resp, err := cmdSvc.VerifyCommand(CommandVerifyRequest{
		CommandID:   cmd.ID,
		PayloadHash: cmd.PayloadHash,
		Signature:   cmd.Signature,
		Nonce:       cmd.Nonce,
	})
	if err != nil {
		t.Fatalf("VerifyCommand: %v", err)
	}
	if !resp.Valid {
		t.Fatalf("command should be valid: %s", resp.Message)
	}
}

func TestCommandReplayPrevention(t *testing.T) {
	cmdSvc, _ := newTestCommandSigning(t)

	cmd, _ := cmdSvc.IssueCommand(IssueCommandRequest{
		CommandType: "config_update",
		TargetID:    "agt-002",
		Payload:     `{"dns":"1.1.1.1"}`,
	}, "ops")

	// First verification should succeed
	resp1, _ := cmdSvc.VerifyCommand(CommandVerifyRequest{
		CommandID:   cmd.ID,
		PayloadHash: cmd.PayloadHash,
		Signature:   cmd.Signature,
		Nonce:       cmd.Nonce,
	})
	if !resp1.Valid {
		t.Fatal("first verification should pass")
	}

	// Second verification (replay) should fail
	resp2, _ := cmdSvc.VerifyCommand(CommandVerifyRequest{
		CommandID:   cmd.ID,
		PayloadHash: cmd.PayloadHash,
		Signature:   cmd.Signature,
		Nonce:       cmd.Nonce,
	})
	if resp2.Valid {
		t.Fatal("replay should be rejected")
	}
	if resp2.Message != "Nonce already used (replay detected)" {
		t.Fatalf("unexpected message: %s", resp2.Message)
	}
}

func TestCommandNonceMismatch(t *testing.T) {
	cmdSvc, _ := newTestCommandSigning(t)

	cmd, _ := cmdSvc.IssueCommand(IssueCommandRequest{
		CommandType: "agent_upgrade",
		TargetID:    "agt-003",
		Payload:     `{"version":"3.0"}`,
	}, "ops")

	resp, _ := cmdSvc.VerifyCommand(CommandVerifyRequest{
		CommandID:   cmd.ID,
		PayloadHash: cmd.PayloadHash,
		Signature:   cmd.Signature,
		Nonce:       "wrong-nonce",
	})
	if resp.Valid {
		t.Fatal("wrong nonce should be rejected")
	}
}

func TestCommandPayloadHashMismatch(t *testing.T) {
	cmdSvc, _ := newTestCommandSigning(t)

	cmd, _ := cmdSvc.IssueCommand(IssueCommandRequest{
		CommandType: "revoke_agent",
		TargetID:    "*",
		Payload:     `{"agent":"agt-bad"}`,
	}, "admin")

	tamperedHash := sha256.Sum256([]byte("tampered payload"))
	resp, _ := cmdSvc.VerifyCommand(CommandVerifyRequest{
		CommandID:   cmd.ID,
		PayloadHash: hex.EncodeToString(tamperedHash[:]),
		Signature:   cmd.Signature,
		Nonce:       cmd.Nonce,
	})
	if resp.Valid {
		t.Fatal("tampered payload hash should be rejected")
	}
}

func TestCommandUnknown(t *testing.T) {
	cmdSvc, _ := newTestCommandSigning(t)
	resp, _ := cmdSvc.VerifyCommand(CommandVerifyRequest{
		CommandID:   "cmd-nonexistent",
		PayloadHash: "abc",
		Signature:   "def",
		Nonce:       "ghi",
	})
	if resp.Valid {
		t.Fatal("unknown command should not verify")
	}
}

func TestCommandDefaultTTL(t *testing.T) {
	cmdSvc, _ := newTestCommandSigning(t)

	cmd, err := cmdSvc.IssueCommand(IssueCommandRequest{
		CommandType: "tunnel_restart",
		TargetID:    "agt-005",
		Payload:     `{}`,
		TTLMinutes:  0, // should default to 15 minutes
	}, "ops")
	if err != nil {
		t.Fatal(err)
	}
	// ExpiresAt should be approximately 15 minutes from now
	ttl := cmd.ExpiresAt.Sub(cmd.IssuedAt)
	if ttl < 14*60*1e9 || ttl > 16*60*1e9 { // rough bounds in nanoseconds
		t.Fatalf("expected ~15min TTL, got %v", ttl)
	}
}

func TestListCommands(t *testing.T) {
	cmdSvc, _ := newTestCommandSigning(t)
	cmdSvc.IssueCommand(IssueCommandRequest{CommandType: "a", TargetID: "t1", Payload: "p1"}, "u")
	cmdSvc.IssueCommand(IssueCommandRequest{CommandType: "b", TargetID: "t2", Payload: "p2"}, "u")

	cmds := cmdSvc.ListCommands()
	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(cmds))
	}
}

func TestGetCommand(t *testing.T) {
	cmdSvc, _ := newTestCommandSigning(t)
	cmd, _ := cmdSvc.IssueCommand(IssueCommandRequest{CommandType: "test", TargetID: "t", Payload: "p"}, "u")

	got, err := cmdSvc.GetCommand(cmd.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != cmd.ID {
		t.Fatalf("ID mismatch: %s vs %s", got.ID, cmd.ID)
	}
}

func TestGetCommandNotFound(t *testing.T) {
	cmdSvc, _ := newTestCommandSigning(t)
	_, err := cmdSvc.GetCommand("cmd-ghost")
	if err == nil {
		t.Fatal("expected error for nonexistent command")
	}
}

func TestGetPendingCommands(t *testing.T) {
	cmdSvc, _ := newTestCommandSigning(t)
	cmdSvc.IssueCommand(IssueCommandRequest{CommandType: "a", TargetID: "agt-10", Payload: "p1"}, "u")
	cmdSvc.IssueCommand(IssueCommandRequest{CommandType: "b", TargetID: "agt-10", Payload: "p2"}, "u")
	cmdSvc.IssueCommand(IssueCommandRequest{CommandType: "c", TargetID: "agt-20", Payload: "p3"}, "u")
	cmdSvc.IssueCommand(IssueCommandRequest{CommandType: "d", TargetID: "*", Payload: "p4"}, "u") // broadcast

	pending := cmdSvc.GetPendingCommands("agt-10")
	// Should include the 2 targeted + 1 broadcast
	if len(pending) != 3 {
		t.Fatalf("expected 3 pending commands for agt-10, got %d", len(pending))
	}

	// Commands for agt-20 should be 1 targeted + 1 broadcast
	pending20 := cmdSvc.GetPendingCommands("agt-20")
	if len(pending20) != 2 {
		t.Fatalf("expected 2 pending commands for agt-20, got %d", len(pending20))
	}
}

func TestCommandMarkedExecutedAfterVerify(t *testing.T) {
	cmdSvc, _ := newTestCommandSigning(t)
	cmd, _ := cmdSvc.IssueCommand(IssueCommandRequest{CommandType: "test", TargetID: "agt-1", Payload: "p"}, "u")

	// Verify
	cmdSvc.VerifyCommand(CommandVerifyRequest{
		CommandID:   cmd.ID,
		PayloadHash: cmd.PayloadHash,
		Signature:   cmd.Signature,
		Nonce:       cmd.Nonce,
	})

	// Now it should not appear in pending
	pending := cmdSvc.GetPendingCommands("agt-1")
	if len(pending) != 0 {
		t.Fatalf("executed command should not appear in pending, got %d", len(pending))
	}
}
