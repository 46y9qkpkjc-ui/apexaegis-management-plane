package profiles

import "testing"

// Compile-time interface check
var _ ProfileStore = (*Store)(nil)

func TestStore_ListByType(t *testing.T) {
	s := NewStore()

	for _, pt := range []ProfileType{TypeATP, TypeSSL, TypeDNS, TypeWeb, TypeDevicePosture} {
		list := s.List(pt)
		if len(list) == 0 {
			t.Errorf("expected default profiles for type %s, got none", pt)
		}
	}
}

func TestStore_GetProfile(t *testing.T) {
	s := NewStore()

	list := s.List(TypeATP)
	if len(list) == 0 {
		t.Fatal("no ATP profiles")
	}

	p, ok := s.Get(list[0].ID)
	if !ok {
		t.Fatal("expected to find profile by ID")
	}
	if p.Name == "" {
		t.Error("profile name should not be empty")
	}
}

func TestStore_GetMissing(t *testing.T) {
	s := NewStore()
	_, ok := s.Get("nonexistent")
	if ok {
		t.Error("expected not found for nonexistent profile")
	}
}

func TestStore_CreateAndDelete(t *testing.T) {
	s := NewStore()

	p, err := s.Create(&Profile{
		Type: TypeATP,
		Name: "Custom ATP",
	}, "admin")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if p.ID == "" {
		t.Error("expected generated ID")
	}

	// Verify it appears in list
	found := false
	for _, lp := range s.List(TypeATP) {
		if lp.ID == p.ID {
			found = true
		}
	}
	if !found {
		t.Error("created profile not in list")
	}

	// Delete it
	if err := s.Delete(p.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, ok := s.Get(p.ID)
	if ok {
		t.Error("expected profile to be deleted")
	}
}

func TestStore_DeleteBuiltin(t *testing.T) {
	s := NewStore()

	list := s.List(TypeATP)
	var builtinID string
	for _, p := range list {
		if p.Builtin {
			builtinID = p.ID
			break
		}
	}
	if builtinID == "" {
		t.Skip("no builtin profiles to test")
	}

	err := s.Delete(builtinID)
	if err == nil {
		t.Error("expected error deleting builtin profile")
	}
}

func TestStore_Update(t *testing.T) {
	s := NewStore()

	p, _ := s.Create(&Profile{
		Type: TypeDNS,
		Name: "My DNS",
	}, "admin")

	updated, err := s.Update(p.ID, &Profile{Name: "Renamed DNS"}, "admin")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "Renamed DNS" {
		t.Errorf("expected name 'Renamed DNS', got %q", updated.Name)
	}
}

func TestStore_Toggle(t *testing.T) {
	s := NewStore()

	p, _ := s.Create(&Profile{
		Type:    TypeWeb,
		Name:    "Toggle Test",
		Enabled: true,
	}, "admin")

	toggled, err := s.Toggle(p.ID, false, "admin")
	if err != nil {
		t.Fatalf("toggle: %v", err)
	}
	if toggled.Enabled {
		t.Error("expected profile to be disabled")
	}
}
