package handlers

import (
	"encoding/json"
	"testing"

	"github.com/zcp/management-plane/internal/db"
)

func TestApplyUserPatchOktaPathlessReplace(t *testing.T) {
	user := &db.SCIMUser{
		Email:  "old@example.com",
		Name:   "Old Name",
		Status: "active",
	}
	value := json.RawMessage(`{
		"userName":"new@example.com",
		"name":{"formatted":"New Name"},
		"active":false
	}`)

	if err := applyUserPatch(user, scimPatchOperation{Op: "replace", Value: value}); err != nil {
		t.Fatalf("applyUserPatch returned error: %v", err)
	}
	if user.Email != "new@example.com" || user.Name != "New Name" || user.Status != "suspended" {
		t.Fatalf("unexpected patched user: %+v", user)
	}
}

func TestMemberPathValueOktaRemove(t *testing.T) {
	got := memberPathValue(`members[value eq "b0000000-0000-0000-0000-000000000001"]`)
	if got != "b0000000-0000-0000-0000-000000000001" {
		t.Fatalf("unexpected member ID: %q", got)
	}
}

func TestPatchMembersOktaArray(t *testing.T) {
	values, err := patchMembers(json.RawMessage(`[
		{"value":"user-1"},
		{"value":"user-2"}
	]`))
	if err != nil {
		t.Fatalf("patchMembers returned error: %v", err)
	}
	if len(values) != 2 || values[0] != "user-1" || values[1] != "user-2" {
		t.Fatalf("unexpected members: %#v", values)
	}
}
