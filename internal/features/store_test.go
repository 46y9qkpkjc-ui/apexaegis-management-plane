package features

import "testing"

// Compile-time interface check
var _ FeatureStore = (*Store)(nil)

func TestStore_ListAndGet(t *testing.T) {
	s := NewStore()

	all := s.List()
	if len(all) == 0 {
		t.Fatal("expected default features, got none")
	}

	f, ok := s.Get("ztna")
	if !ok {
		t.Fatal("expected to find 'ztna' feature")
	}
	if f.Name == "" {
		t.Error("feature name should not be empty")
	}
}

func TestStore_GetMissing(t *testing.T) {
	s := NewStore()
	_, ok := s.Get("nonexistent-feature")
	if ok {
		t.Error("expected not found for nonexistent feature")
	}
}

func TestStore_Toggle(t *testing.T) {
	s := NewStore()

	// Toggle off
	f, err := s.Toggle("ztna", false, "enterprise", "admin")
	if err != nil {
		t.Fatalf("toggle off: %v", err)
	}
	if f.Enabled {
		t.Error("expected feature to be disabled")
	}

	// Toggle back on
	f, err = s.Toggle("ztna", true, "enterprise", "admin")
	if err != nil {
		t.Fatalf("toggle on: %v", err)
	}
	if !f.Enabled {
		t.Error("expected feature to be enabled")
	}
}

func TestStore_TogglePlanGating(t *testing.T) {
	s := NewStore()

	// Try to enable an enterprise feature with a free plan
	_, err := s.Toggle("ztna", true, "free", "admin")
	if err == nil {
		t.Error("expected error toggling enterprise feature on free plan")
	}
}

func TestStore_StartTrial(t *testing.T) {
	s := NewStore()

	// "sandboxing" starts disabled and has TrialDays=14
	f, err := s.StartTrial("sandboxing", "admin")
	if err != nil {
		t.Fatalf("start trial: %v", err)
	}
	if !f.Enabled {
		t.Error("expected feature enabled after trial start")
	}
	if f.TrialEnd == "" {
		t.Error("expected trial_end to be set")
	}
}

func TestStore_IsEnabled(t *testing.T) {
	s := NewStore()

	if !s.IsEnabled("ztna") {
		t.Error("ztna should be enabled by default")
	}
	if s.IsEnabled("nonexistent") {
		t.Error("nonexistent feature should not be enabled")
	}
}
