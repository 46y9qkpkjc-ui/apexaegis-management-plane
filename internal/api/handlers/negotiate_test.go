package handlers

import "testing"

// allowedRedirect is the open-redirect guard for the SPNEGO landing target — only
// the ApexAegis console origins (and localhost in dev) may be redirected to after
// a Kerberos sign-in, so a crafted redirect_uri can't exfiltrate the one-time code.
func TestAllowedRedirect(t *testing.T) {
	cases := []struct {
		uri  string
		want bool
	}{
		{"https://www.apexaegis.app/login", true},
		{"https://apexaegis.app/login", true},
		{"https://store.apexaegis.app/login", true},
		{"http://localhost:3000/login", true},
		{"http://127.0.0.1:3010/login", true},
		{"", false},
		{"https://evil.com/login", false},
		{"https://apexaegis.app.evil.com/", false},     // suffix trick
		{"https://evil-apexaegis.app/", false},          // no dot boundary
		{"javascript:alert(1)", false},                  // non-http scheme
		{"ftp://apexaegis.app/", false},
		{"not a url at all", false},
	}
	for _, tc := range cases {
		if got := allowedRedirect(tc.uri); got != tc.want {
			t.Errorf("allowedRedirect(%q) = %v, want %v", tc.uri, got, tc.want)
		}
	}
}
