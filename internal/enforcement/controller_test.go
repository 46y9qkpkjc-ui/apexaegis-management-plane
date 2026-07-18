package enforcement

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"
)

type fakeEnforcer struct {
	disconnectCalls int
	quarantineCalls int
	lastVLAN        int
	lastACL         string
	ackDisconnect   bool
	ackQuarantine   bool
	err             error
}

func (f *fakeEnforcer) Disconnect(_ context.Context, _ string) (bool, error) {
	f.disconnectCalls++
	return f.ackDisconnect, f.err
}
func (f *fakeEnforcer) Quarantine(_ context.Context, _ string, vlan int, acl string) (bool, error) {
	f.quarantineCalls++
	f.lastVLAN, f.lastACL = vlan, acl
	return f.ackQuarantine, f.err
}

func TestRespondToRisk_Quarantine(t *testing.T) {
	fe := &fakeEnforcer{ackQuarantine: true}
	c := NewController(fe, ActionQuarantine, 999, "quarantine-acl", zap.NewNop())

	acted, err := c.RespondToRisk(context.Background(), "dev-cn", "org-1", "posture drop")
	if err != nil || !acted {
		t.Fatalf("acted=%v err=%v; want acted=true, nil", acted, err)
	}
	if fe.quarantineCalls != 1 || fe.disconnectCalls != 0 {
		t.Fatalf("calls: quarantine=%d disconnect=%d; want 1/0", fe.quarantineCalls, fe.disconnectCalls)
	}
	if fe.lastVLAN != 999 || fe.lastACL != "quarantine-acl" {
		t.Errorf("CoA args: vlan=%d acl=%q; want 999/quarantine-acl", fe.lastVLAN, fe.lastACL)
	}
}

func TestRespondToRisk_Disconnect(t *testing.T) {
	fe := &fakeEnforcer{ackDisconnect: true}
	c := NewController(fe, ActionDisconnect, 0, "", zap.NewNop())
	if _, err := c.RespondToRisk(context.Background(), "dev-cn", "org-1", "drop"); err != nil {
		t.Fatal(err)
	}
	if fe.disconnectCalls != 1 || fe.quarantineCalls != 0 {
		t.Fatalf("want a single Disconnect; got disconnect=%d quarantine=%d", fe.disconnectCalls, fe.quarantineCalls)
	}
}

func TestRespondToRisk_OffIsNoop(t *testing.T) {
	fe := &fakeEnforcer{}
	c := NewController(fe, ActionOff, 999, "", zap.NewNop())
	if c.Enabled() {
		t.Fatal("ActionOff must not be Enabled")
	}
	acted, err := c.RespondToRisk(context.Background(), "dev-cn", "org", "drop")
	if acted || err != nil {
		t.Fatalf("off action acted=%v err=%v; want false,nil", acted, err)
	}
	if fe.quarantineCalls != 0 || fe.disconnectCalls != 0 {
		t.Fatal("off action must not call the enforcer")
	}
}

func TestRespondToRisk_NilEnforcerSafe(t *testing.T) {
	c := NewController(nil, ActionQuarantine, 999, "", zap.NewNop())
	if c.Enabled() {
		t.Fatal("nil enforcer must not be Enabled")
	}
	if _, err := c.RespondToRisk(context.Background(), "d", "o", "r"); err != nil {
		t.Fatalf("nil enforcer should be a safe no-op, got %v", err)
	}
}

func TestRespondToRisk_NoLiveSessionIsBenign(t *testing.T) {
	// The enforcer returns the radsec "no live NAS session" error — the device is
	// off-network. That's not a failure; nothing to cut.
	fe := &fakeEnforcer{err: errors.New("radsec: no live NAS session for the given key")}
	c := NewController(fe, ActionDisconnect, 0, "", zap.NewNop())
	acted, err := c.RespondToRisk(context.Background(), "dev-cn", "org", "drop")
	if err != nil {
		t.Fatalf("no-live-session must be benign, got err=%v", err)
	}
	if acted {
		t.Fatal("no-live-session cannot report acted")
	}
}

func TestRespondToRisk_RealErrorPropagates(t *testing.T) {
	fe := &fakeEnforcer{err: errors.New("write dynamic-auth request: broken pipe")}
	c := NewController(fe, ActionDisconnect, 0, "", zap.NewNop())
	if _, err := c.RespondToRisk(context.Background(), "d", "o", "r"); err == nil {
		t.Fatal("a genuine transport error must propagate")
	}
}
