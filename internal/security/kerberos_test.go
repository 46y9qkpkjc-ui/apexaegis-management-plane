package security

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"go.uber.org/zap"
)

// testKeytabB64 builds a valid single-entry keytab for the MP's SPN and returns
// it base64-encoded, exactly as it would arrive via MP_KRB5_KEYTAB_B64.
func testKeytabB64(t *testing.T) string {
	t.Helper()
	kt := keytab.New()
	if err := kt.AddEntry("HTTP/api.apexaegis.app", "AD.APEXAEGIS.APP", "s3cr3t-svc-pass", time.Unix(1_700_000_000, 0), 2, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}
	raw, err := kt.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestNewKerberosValidator_ConfigErrors(t *testing.T) {
	log := zap.NewNop()
	cases := map[string]string{
		"empty":        "",
		"bad base64":   "!!!not-base64!!!",
		"not-a-keytab": base64.StdEncoding.EncodeToString([]byte("this is not a keytab")),
		"blank/space":  "   ",
	}
	for name, ktB64 := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewKerberosValidator(ktB64, "HTTP/api.apexaegis.app@AD.APEXAEGIS.APP", "AD.APEXAEGIS.APP", log); err == nil {
				t.Fatalf("expected error for %q keytab, got nil", name)
			}
		})
	}
}

func TestNewKerberosValidator_Valid(t *testing.T) {
	v, err := NewKerberosValidator(testKeytabB64(t), "HTTP/api.apexaegis.app@AD.APEXAEGIS.APP", "ad.apexaegis.app", zap.NewNop())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.SPN() != "HTTP/api.apexaegis.app@AD.APEXAEGIS.APP" {
		t.Errorf("SPN() = %q", v.SPN())
	}
	if v.Realm() != "AD.APEXAEGIS.APP" { // normalized to upper-case
		t.Errorf("Realm() = %q, want AD.APEXAEGIS.APP", v.Realm())
	}
}

func TestKerberosValidator_ValidateRejectsGarbage(t *testing.T) {
	v, err := NewKerberosValidator(testKeytabB64(t), "", "AD.APEXAEGIS.APP", zap.NewNop())
	if err != nil {
		t.Fatalf("build validator: %v", err)
	}
	cases := map[string]string{
		"empty":                 "",
		"negotiate empty":       "Negotiate ",
		"non-base64":            "@@@not base64@@@",
		"valid b64, non-spnego": base64.StdEncoding.EncodeToString([]byte("\x00\x01\x02 definitely not a SPNEGO token")),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			id, err := v.Validate(tok)
			if err == nil {
				t.Fatalf("expected error, got identity %+v", id)
			}
			if id != nil {
				t.Fatalf("expected nil identity on error, got %+v", id)
			}
		})
	}
}
