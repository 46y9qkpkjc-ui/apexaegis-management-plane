package tools

import (
	"testing"
	"time"
)

// ParseRDAP is the one whois piece with no network — lock the field extraction
// (age from the registration event, registrar/registrant from the jCard, NS).
func TestParseRDAP(t *testing.T) {
	body := []byte(`{
	  "ldhName": "Example.COM",
	  "events": [
	    {"eventAction":"registration","eventDate":"2020-01-01T00:00:00Z"},
	    {"eventAction":"expiration","eventDate":"2030-01-01T00:00:00Z"}
	  ],
	  "entities": [
	    {"roles":["registrar"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","MarkMonitor Inc."]]]},
	    {"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Acme"],["org",{},"text","Acme Corp"],["adr",{},"text",["","","","","","","US"]]]]}
	  ],
	  "nameservers": [{"ldhName":"a.iana-servers.net"},{"ldhName":"b.iana-servers.net"}]
	}`)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	r, err := ParseRDAP(body, now)
	if err != nil {
		t.Fatalf("ParseRDAP: %v", err)
	}
	if r.RegistrableDomain != "example.com" {
		t.Errorf("domain = %q", r.RegistrableDomain)
	}
	if r.AgeDays < 1820 || r.AgeDays > 1830 { // ~5 years
		t.Errorf("age_days = %d, want ~1826", r.AgeDays)
	}
	if r.Registrar != "MarkMonitor Inc." {
		t.Errorf("registrar = %q", r.Registrar)
	}
	if r.RegistrantOrg != "Acme Corp" || r.RegistrantCountry != "US" {
		t.Errorf("registrant = %q / %q", r.RegistrantOrg, r.RegistrantCountry)
	}
	if r.PrivacyProtected {
		t.Error("should not be privacy-protected (org present)")
	}
	if len(r.Nameservers) != 2 {
		t.Errorf("nameservers = %v", r.Nameservers)
	}

	// Redacted registrant → privacy_protected.
	redacted := []byte(`{"ldhName":"x.com","entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","REDACTED"]]]}]}`)
	rr, _ := ParseRDAP(redacted, now)
	if !rr.PrivacyProtected {
		t.Error("redacted registrant should be privacy-protected")
	}
}
