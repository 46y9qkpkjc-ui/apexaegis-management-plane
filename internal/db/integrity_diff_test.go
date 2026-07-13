package db

import "testing"

func TestIntegrityDiff(t *testing.T) {
	base := map[string]string{"c:\\agent.exe": "aa", "boot.sys": "bb", "run\\key": "cc"}
	// tampered: agent.exe modified, boot.sys removed, evil.exe added
	cur := map[string]string{"c:\\agent.exe": "XX", "run\\key": "cc", "evil.exe": "dd"}
	mod, add, rem := IntegrityDiff(base, cur)
	if len(mod) != 1 || mod[0] != "c:\\agent.exe" {
		t.Fatalf("modified=%v want [c:\\agent.exe]", mod)
	}
	if len(rem) != 1 || rem[0] != "boot.sys" {
		t.Fatalf("removed=%v want [boot.sys]", rem)
	}
	if len(add) != 1 || add[0] != "evil.exe" {
		t.Fatalf("added=%v want [evil.exe]", add)
	}
	// clean: identical → no drift
	if m, _, r := IntegrityDiff(base, base); len(m) != 0 || len(r) != 0 {
		t.Fatalf("clean diff reported drift: mod=%v rem=%v", m, r)
	}
}
