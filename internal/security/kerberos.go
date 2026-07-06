package security

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"go.uber.org/zap"
)

// spnegoCredsContextKey mirrors gokrb5's unexported context key under which
// AcceptSecContext stores the validated *credentials.Credentials
// (spnego/http.go: `ctxCredentials`). Context keys compare by value and this key
// is a plain (untyped) string constant, so an identical string reads it back.
// Pinned to gokrb5 v8.4.4 — revisit if the dependency is bumped.
const spnegoCredsContextKey = "github.com/jcmturner/gokrb5/v8/ctxCredentials"

// KerberosIdentity is the authenticated principal extracted from a validated
// SPNEGO token.
type KerberosIdentity struct {
	Username  string   // client principal short name (AD sAMAccountName), e.g. "jsmith"
	Realm     string   // Kerberos realm, e.g. "AD.APEXAEGIS.APP"
	Principal string   // Username@Realm
	FullName  string   // display name (only when PAC decoding is enabled)
	GroupSIDs []string // AD group SIDs (only when PAC decoding is enabled)
}

// KerberosValidator performs OFFLINE SPNEGO/Kerberos ticket validation using a
// service keytab. It NEVER contacts the KDC/DC: the client's service ticket is
// decrypted and verified with the service key held in the keytab. This is why
// MP-side validation is compatible with the "DC line-of-sight only via the
// gateway" invariant — the client acquires its ticket over the gateway
// machine-tunnel; the MP only needs the keytab (delivered via SSM SecureString).
type KerberosValidator struct {
	kt     *keytab.Keytab
	spn    string // informational: HTTP/api.apexaegis.app@AD.APEXAEGIS.APP
	realm  string // expected realm (uppercased); empty disables the realm check
	logger *zap.Logger
}

// NewKerberosValidator builds a validator from a base64-encoded keytab (as
// stored in SSM SecureString and injected via the MP_KRB5_KEYTAB_B64 env var).
// spn/realm are non-secret and passed as plain env (MP_KRB5_SPN/MP_KRB5_REALM).
func NewKerberosValidator(keytabB64, spn, realm string, logger *zap.Logger) (*KerberosValidator, error) {
	keytabB64 = strings.TrimSpace(keytabB64)
	if keytabB64 == "" {
		return nil, fmt.Errorf("kerberos: empty keytab")
	}
	raw, err := base64.StdEncoding.DecodeString(keytabB64)
	if err != nil {
		return nil, fmt.Errorf("kerberos: decode keytab base64: %w", err)
	}
	kt := keytab.New()
	if err := kt.Unmarshal(raw); err != nil {
		return nil, fmt.Errorf("kerberos: parse keytab: %w", err)
	}
	return &KerberosValidator{
		kt:     kt,
		spn:    strings.TrimSpace(spn),
		realm:  strings.ToUpper(strings.TrimSpace(realm)),
		logger: logger,
	}, nil
}

// SPN returns the configured service principal name (informational).
func (v *KerberosValidator) SPN() string { return v.spn }

// Realm returns the configured/expected realm.
func (v *KerberosValidator) Realm() string { return v.realm }

// Validate decodes and validates a base64 SPNEGO token (the value a client
// would send in an "Authorization: Negotiate <token>" header) and returns the
// authenticated principal. Validation is entirely offline against the keytab.
func (v *KerberosValidator) Validate(spnegoToken string) (*KerberosIdentity, error) {
	tok := strings.TrimSpace(spnegoToken)
	// Tolerate a full "Negotiate <b64>" header value.
	if strings.HasPrefix(strings.ToLower(tok), "negotiate ") {
		tok = strings.TrimSpace(tok[len("negotiate "):])
	}
	if tok == "" {
		return nil, fmt.Errorf("kerberos: empty spnego token")
	}
	raw, err := base64.StdEncoding.DecodeString(tok)
	if err != nil {
		return nil, fmt.Errorf("kerberos: decode spnego token: %w", err)
	}

	var st spnego.SPNEGOToken
	if err := st.Unmarshal(raw); err != nil {
		return nil, fmt.Errorf("kerberos: unmarshal spnego token: %w", err)
	}

	// DecodePAC(false): we only need the client principal (from the AP-REQ
	// authenticator cname, set regardless of PAC). Group membership comes from
	// client_user_groups (authoritative for imported groups), so we avoid PAC
	// decoding entirely — no krbtgt dependency, fewer failure modes.
	svc := spnego.SPNEGOService(v.kt, service.DecodePAC(false))

	authed, ctx, status := svc.AcceptSecContext(&st)
	if !authed || status.Code != gssapi.StatusComplete {
		return nil, fmt.Errorf("kerberos: spnego validation failed (code=%d): %s", status.Code, status.Message)
	}

	creds, ok := ctx.Value(spnegoCredsContextKey).(*credentials.Credentials)
	if !ok || creds == nil {
		return nil, fmt.Errorf("kerberos: validated context missing credentials")
	}

	id := &KerberosIdentity{
		Username: strings.TrimSpace(creds.UserName()),
		Realm:    strings.ToUpper(strings.TrimSpace(creds.Domain())),
	}
	if id.Username == "" {
		return nil, fmt.Errorf("kerberos: validated ticket has empty principal")
	}
	if id.Realm == "" {
		id.Realm = v.realm
	}
	// Enforce the configured realm if one is set — a valid ticket from an
	// unexpected realm must not be accepted.
	if v.realm != "" && !strings.EqualFold(id.Realm, v.realm) {
		return nil, fmt.Errorf("kerberos: principal realm %q does not match expected realm %q", id.Realm, v.realm)
	}
	id.Principal = id.Username + "@" + id.Realm

	if ad := creds.GetADCredentials(); ad.EffectiveName != "" || len(ad.GroupMembershipSIDs) > 0 {
		id.FullName = ad.FullName
		id.GroupSIDs = ad.GroupMembershipSIDs
	}
	return id, nil
}
