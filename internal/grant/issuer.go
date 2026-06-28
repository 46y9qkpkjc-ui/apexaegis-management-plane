// Package grant mints the session-grant JWTs that the private-access gateway
// verifies. It is the issuing counterpart to the gateway's offline verifier
// (github.com/apexaegis/private-gateway internal/grant): same compact HS256 JWT,
// same claim names, same issuer — so a grant minted here is accepted there with
// no shared code, only a shared signing key (PRIVATE_ACCESS_GRANT_SIGNING_KEY).
//
// Two grant shapes:
//   - user   — post-logon, carries a user subject, one app target.
//   - device — pre-logon machine tunnel, no subject. A device grant may carry a
//     DC-scope port set (tgt_ports): ONE grant authorizing the DC host across its
//     Kerberos/domain service ports (53/88/389/445/464/123 …); the gateway pins
//     the host and admits one stream per port in the set.
package grant

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Grant types — must match the gateway verifier.
const (
	TypeUser   = "user"
	TypeDevice = "device"
)

// DefaultIssuer is the iss claim the gateway pins.
const DefaultIssuer = "device-api.apexaegis.app"

// Claims is the grant JWT payload. The json tags MUST stay identical to the
// gateway's JWTClaims, or verification breaks.
type Claims struct {
	Issuer      string `json:"iss"`
	Subject     string `json:"sub,omitempty"` // user_id; empty for device grants
	DeviceID    string `json:"did"`           // device cert CN; gateway cross-checks vs mTLS
	Type        string `json:"typ"`           // "user" | "device"
	AppID       string `json:"app"`
	TargetHost  string `json:"tgt_host"`
	TargetPort  int    `json:"tgt_port"`
	TargetPorts []int  `json:"tgt_ports,omitempty"` // DC-scope machine-tunnel set
	Protocol    string `json:"proto"`
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
	JWTID       string `json:"jti"` // unique grant id (replay prevention)
}

// Issuer mints HS256 grants signed with the shared management-plane key.
type Issuer struct {
	signingKey []byte
	issuer     string
	ttl        time.Duration
}

// Option configures an Issuer.
type Option func(*Issuer)

// WithIssuer overrides the iss claim (defaults to DefaultIssuer).
func WithIssuer(iss string) Option {
	return func(i *Issuer) {
		if iss != "" {
			i.issuer = iss
		}
	}
}

// WithTTL overrides the grant lifetime (defaults to 5m). Keep it short — grants
// are bearer tokens and a short TTL bounds the blast radius of a leak.
func WithTTL(d time.Duration) Option {
	return func(i *Issuer) {
		if d > 0 {
			i.ttl = d
		}
	}
}

// NewIssuer builds an Issuer from the base64 (or raw) shared signing key — the
// same key the gateways verify with.
func NewIssuer(signingKeyBase64 string, opts ...Option) (*Issuer, error) {
	key, err := base64.StdEncoding.DecodeString(signingKeyBase64)
	if err != nil {
		key = []byte(signingKeyBase64) // accept raw bytes too
	}
	if len(key) < 32 {
		return nil, fmt.Errorf("grant signing key too short (%d bytes); need >=32", len(key))
	}
	i := &Issuer{signingKey: key, issuer: DefaultIssuer, ttl: 5 * time.Minute}
	for _, o := range opts {
		o(i)
	}
	return i, nil
}

// UserGrant mints a post-logon user grant for one app target.
func (i *Issuer) UserGrant(userID, deviceID, appID, targetHost string, targetPort int) (string, error) {
	if userID == "" {
		return "", fmt.Errorf("user grant requires a user id")
	}
	return i.mint(Claims{
		Subject:    userID,
		DeviceID:   deviceID,
		Type:       TypeUser,
		AppID:      appID,
		TargetHost: targetHost,
		TargetPort: targetPort,
		Protocol:   "tcp",
	})
}

// DeviceGrant mints a pre-logon device grant for a single target.
func (i *Issuer) DeviceGrant(deviceID, appID, targetHost string, targetPort int) (string, error) {
	return i.mint(Claims{
		DeviceID:   deviceID,
		Type:       TypeDevice,
		AppID:      appID,
		TargetHost: targetHost,
		TargetPort: targetPort,
		Protocol:   "tcp",
	})
}

// DCScopeGrant mints the machine-tunnel device grant: ONE grant authorizing the
// DC host across its service-port set. The gateway pins the host to dcHost and
// admits one stream per port in the set (TCP-first).
func (i *Issuer) DCScopeGrant(deviceID, appID, dcHost string, ports []int) (string, error) {
	if dcHost == "" {
		return "", fmt.Errorf("DC-scope grant requires a DC host")
	}
	if len(ports) == 0 {
		return "", fmt.Errorf("DC-scope grant requires at least one port")
	}
	return i.mint(Claims{
		DeviceID:    deviceID,
		Type:        TypeDevice,
		AppID:       appID,
		TargetHost:  dcHost,
		TargetPorts: ports,
		Protocol:    "tcp",
	})
}

// mint fills issuer/time/jti and returns the signed compact JWT.
func (i *Issuer) mint(c Claims) (string, error) {
	if c.DeviceID == "" {
		return "", fmt.Errorf("grant requires a device id")
	}
	now := time.Now()
	c.Issuer = i.issuer
	c.IssuedAt = now.Unix()
	c.ExpiresAt = now.Add(i.ttl).Unix()
	if c.JWTID == "" {
		c.JWTID = newJTI()
	}
	return sign(i.signingKey, c)
}

func newJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// sign produces base64url(header).base64url(payload).base64url(HMAC-SHA256),
// byte-compatible with the gateway's manual verifier.
func sign(key []byte, c Claims) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadJSON, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(header + "." + payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return header + "." + payload + "." + sig, nil
}
