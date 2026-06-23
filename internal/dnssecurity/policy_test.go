package dnssecurity

import "testing"

// The most important invariant: a disabled flag must never block, even if deny
// categories are stored from a previous configuration.
func TestFromSettings_FlagOffNeverBlocks(t *testing.T) {
	p := FromSettings(false, map[string]any{
		"categories": map[string]any{"nrd": "deny", "malicious": "deny"},
	})
	if p.Enabled {
		t.Fatal("flag off must yield a disabled policy")
	}
	if len(p.Categories) != 0 {
		t.Fatalf("flag off must yield no categories, got %v", p.Categories)
	}
	if p.Denies(CategoryMalicious) {
		t.Fatal("disabled policy must not deny any category")
	}
}

// Flag on with no stored config: every category defaults to deny (fail-secure).
func TestFromSettings_FailSecureDefaults(t *testing.T) {
	p := FromSettings(true, nil)
	if !p.Enabled {
		t.Fatal("expected enabled policy")
	}
	for _, c := range Categories {
		if p.Categories[c] != ActionDeny {
			t.Fatalf("category %s default = %q, want deny", c, p.Categories[c])
		}
	}
}

// Flag on honors explicit allow while leaving others fail-secure.
func TestFromSettings_HonorsAllow(t *testing.T) {
	p := FromSettings(true, map[string]any{
		"categories": map[string]any{"nrd": "allow"},
	})
	if p.Denies(CategoryNRD) {
		t.Fatal("nrd explicitly allowed must not be denied")
	}
	if !p.Denies(CategoryMalicious) {
		t.Fatal("unconfigured malicious must remain denied")
	}
}
