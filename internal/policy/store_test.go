package policy

import (
	"testing"

	"go.uber.org/zap"
)

// Compile-time interface check
var _ PolicyStore = (*Store)(nil)

func newTestStore() *Store {
	return NewStore(zap.NewNop())
}

func TestStore_LoadDefaults(t *testing.T) {
	s := newTestStore()
	s.LoadDefaults()

	list := s.List()
	if len(list) < 2 {
		t.Fatalf("expected at least 2 default policies, got %d", len(list))
	}
}

func TestStore_CreateAndGet(t *testing.T) {
	s := newTestStore()

	ver, msg := s.Create(&SecurityPolicy{
		ID:       "test-policy-1",
		OrgID:    "org-1",
		Name:     "Test Policy",
		Sequence: 100,
		Enabled:  true,
		Action:   "allow",
	}, "admin")

	if msg != "" {
		t.Fatalf("create failed: %s", msg)
	}
	if ver < 1 {
		t.Error("expected positive version")
	}

	p, ok := s.Get("test-policy-1")
	if !ok {
		t.Fatal("expected to find created policy")
	}
	if p.Name != "Test Policy" {
		t.Errorf("expected name 'Test Policy', got %q", p.Name)
	}
}

func TestStore_Update(t *testing.T) {
	s := newTestStore()

	s.Create(&SecurityPolicy{
		ID: "upd-1", OrgID: "org-1", Name: "Original", Sequence: 10, Action: "allow",
	}, "admin")

	ver, found, msg := s.Update(&SecurityPolicy{
		ID: "upd-1", OrgID: "org-1", Name: "Updated", Sequence: 10, Action: "deny",
	}, "admin")
	if msg != "" {
		t.Fatalf("update error: %s", msg)
	}
	if !found {
		t.Fatal("expected policy to be found for update")
	}
	if ver < 2 {
		t.Error("expected version bump after update")
	}

	p, _ := s.Get("upd-1")
	if p.Name != "Updated" {
		t.Errorf("expected 'Updated', got %q", p.Name)
	}
}

func TestStore_Delete(t *testing.T) {
	s := newTestStore()

	s.Create(&SecurityPolicy{
		ID: "del-1", OrgID: "org-1", Name: "Delete Me", Sequence: 10, Action: "allow",
	}, "admin")

	_, found, msg := s.Delete("del-1", "admin")
	if msg != "" {
		t.Fatalf("delete error: %s", msg)
	}
	if !found {
		t.Fatal("expected policy to exist for delete")
	}

	_, ok := s.Get("del-1")
	if ok {
		t.Error("expected policy to be gone after delete")
	}
}

func TestStore_DeleteNotFound(t *testing.T) {
	s := newTestStore()

	_, found, _ := s.Delete("nonexistent", "admin")
	if found {
		t.Error("expected not found for nonexistent policy")
	}
}

func TestStore_LockUnlock(t *testing.T) {
	s := newTestStore()

	lock, ok := s.Lock("admin")
	if !ok {
		t.Fatal("expected lock to succeed")
	}
	if lock.LockedBy != "admin" {
		t.Errorf("expected locked_by 'admin', got %q", lock.LockedBy)
	}

	// Can't lock again (different user)
	_, ok = s.Lock("other-user")
	if ok {
		t.Error("expected second lock to fail")
	}

	// Unlock
	if !s.Unlock("admin", false) {
		t.Error("expected unlock to succeed")
	}

	// Verify lock cleared
	if s.GetLock() != nil {
		t.Error("expected no active lock after unlock")
	}
}

func TestStore_VersionControl(t *testing.T) {
	s := newTestStore()

	s.Create(&SecurityPolicy{
		ID: "vc-1", OrgID: "org-1", Name: "V1", Sequence: 10, Action: "allow",
	}, "admin")

	v1 := s.Version()

	s.Update(&SecurityPolicy{
		ID: "vc-1", OrgID: "org-1", Name: "V2", Sequence: 10, Action: "deny",
	}, "admin")

	v2 := s.Version()
	if v2 <= v1 {
		t.Error("expected version to increase after update")
	}

	versions := s.ListVersions()
	if len(versions) < 2 {
		t.Fatalf("expected >= 2 versions, got %d", len(versions))
	}

	cv, ok := s.GetVersion(v1)
	if !ok {
		t.Fatal("expected to find version v1")
	}
	if cv.Version != v1 {
		t.Errorf("expected version %d, got %d", v1, cv.Version)
	}
}

func TestStore_Revert(t *testing.T) {
	s := newTestStore()

	s.Create(&SecurityPolicy{
		ID: "rev-1", OrgID: "org-1", Name: "Before", Sequence: 10, Action: "allow",
	}, "admin")
	v1 := s.Version()

	s.Update(&SecurityPolicy{
		ID: "rev-1", OrgID: "org-1", Name: "After", Sequence: 10, Action: "deny",
	}, "admin")

	_, ok := s.Revert(v1, "admin")
	if !ok {
		t.Fatal("expected revert to succeed")
	}

	p, _ := s.Get("rev-1")
	if p.Name != "Before" {
		t.Errorf("expected 'Before' after revert, got %q", p.Name)
	}
}

func TestStore_OnChange(t *testing.T) {
	s := newTestStore()
	ch := s.OnChange()

	s.Create(&SecurityPolicy{
		ID: "ch-1", OrgID: "org-1", Name: "Change", Sequence: 10, Action: "allow",
	}, "admin")

	select {
	case v := <-ch:
		if v < 1 {
			t.Error("expected positive version on change channel")
		}
	default:
		t.Error("expected change notification")
	}
}

func TestStore_Diff(t *testing.T) {
	s := newTestStore()

	s.Create(&SecurityPolicy{
		ID: "diff-1", OrgID: "org-1", Name: "Diff V1", Sequence: 10, Action: "allow",
	}, "admin")
	v1 := s.Version()

	s.Update(&SecurityPolicy{
		ID: "diff-1", OrgID: "org-1", Name: "Diff V2", Sequence: 10, Action: "deny",
	}, "admin")
	v2 := s.Version()

	diff := s.Diff(v1, v2)
	if len(diff) == 0 {
		t.Error("expected non-empty diff")
	}
}
