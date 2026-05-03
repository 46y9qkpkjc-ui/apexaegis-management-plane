package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// ─── Unified Identity Context (all 6 SGT domains) ──────────────────

// UnifiedIdentity is the normalized identity context produced by the
// broker after merging attributes from external IdPs, device posture,
// network context, and application telemetry.
type UnifiedIdentity struct {
	SessionID string    `json:"session_id"`
	OrgID     string    `json:"org_id"`
	Timestamp time.Time `json:"timestamp"`

	// Domain 1: Identity (from IdP federation)
	Identity IdentityDomain `json:"identity"`

	// Domain 2: Device (from agent posture + MDM)
	Device DeviceDomain `json:"device"`

	// Domain 3: Location (from GeoIP + network intel)
	Location LocationDomain `json:"location"`

	// Domain 4: Application (from gateway proxy inspection)
	Application ApplicationDomain `json:"application"`

	// Domain 5: Data (from DLP engine)
	Data DataDomain `json:"data"`

	// Domain 6: Time (system-derived temporal context)
	Time TimeDomain `json:"time"`

	// Computed
	RiskScore       int      `json:"risk_score"`       // 0-100
	ComplianceState string   `json:"compliance_state"` // compliant, non_compliant, unknown
	EffectiveSGTs   []int    `json:"effective_sgts"`   // resolved SGT values
	Flags           []string `json:"flags"`            // anomaly flags
}

type IdentityDomain struct {
	UserID       string            `json:"user_id"`
	Email        string            `json:"email"`
	DisplayName  string            `json:"display_name"`
	Groups       []string          `json:"groups"`
	Department   string            `json:"department"`
	Title        string            `json:"title"`
	IdPSource    string            `json:"idp_source"` // okta, azure_ad, saml, ldap
	IdPSessionID string            `json:"idp_session_id"`
	MFAVerified  bool              `json:"mfa_verified"`
	MFAMethod    string            `json:"mfa_method"` // totp, webauthn, push
	RiskLevel    string            `json:"risk_level"` // low, medium, high, critical
	Attributes   map[string]string `json:"attributes"`
}

type DeviceDomain struct {
	DeviceID       string `json:"device_id"`
	Hostname       string `json:"hostname"`
	OS             string `json:"os"`
	OSVersion      string `json:"os_version"`
	AgentVersion   string `json:"agent_version"`
	Managed        bool   `json:"managed"`
	Compliant      bool   `json:"compliant"`
	DiskEncrypted  bool   `json:"disk_encrypted"`
	FirewallActive bool   `json:"firewall_active"`
	AntivirusOK    bool   `json:"antivirus_ok"`
	DomainJoined   bool   `json:"domain_joined"`
	EntraJoined    bool   `json:"entra_joined"`
	JailBroken     bool   `json:"jail_broken"`
	CertValid      bool   `json:"cert_valid"`
	MDMSource      string `json:"mdm_source"` // intune, jamf, workspace_one
}

type LocationDomain struct {
	IPAddress     string  `json:"ip_address"`
	Country       string  `json:"country"`
	Region        string  `json:"region"`
	City          string  `json:"city"`
	Latitude      float64 `json:"latitude"`
	Longitude     float64 `json:"longitude"`
	ASN           int     `json:"asn"`
	ISP           string  `json:"isp"`
	NetworkType   string  `json:"network_type"` // corporate, home, public_wifi, cellular, vpn
	TrustedNet    bool    `json:"trusted_network"`
	ProxyDetected bool    `json:"proxy_detected"`
	TorDetected   bool    `json:"tor_detected"`
}

type ApplicationDomain struct {
	AppID      string `json:"app_id"`
	AppName    string `json:"app_name"`
	Category   string `json:"category"`
	RiskScore  int    `json:"risk_score"` // 1-10
	Sanctioned bool   `json:"sanctioned"`
	Protocol   string `json:"protocol"` // https, quic, tls
	DataExfil  bool   `json:"data_exfil_risk"`
}

type DataDomain struct {
	Sensitivity    string   `json:"sensitivity"`    // public, internal, confidential, restricted
	Classification string   `json:"classification"` // none, pii, phi, pci, financial
	DLPTriggered   bool     `json:"dlp_triggered"`
	DLPPolicies    []string `json:"dlp_policies"`
}

type TimeDomain struct {
	LocalTime     time.Time `json:"local_time"`
	UTC           time.Time `json:"utc"`
	BusinessHours bool      `json:"business_hours"`
	Holiday       bool      `json:"holiday"`
	MFAAgeMinutes int       `json:"mfa_age_minutes"`
	SessionAge    int       `json:"session_age_minutes"`
}

// ─── IdP Federation Config ──────────────────────────────────────────

type IdPConfig struct {
	ID           string `json:"id"`
	OrgID        string `json:"org_id"`
	Name         string `json:"name"`
	ProviderType string `json:"provider_type"` // okta, azure_ad, google, saml, ldap, ping
	Enabled      bool   `json:"enabled"`
	IsDefault    bool   `json:"is_default"`

	// OIDC federation
	ClientID      string   `json:"client_id,omitempty"`
	ClientSecret  string   `json:"client_secret,omitempty"` // stored encrypted at rest in production
	IssuerURL     string   `json:"issuer_url,omitempty"`
	JWKSURI       string   `json:"jwks_uri,omitempty"`
	TokenEndpoint string   `json:"token_endpoint,omitempty"`
	Scopes        []string `json:"scopes,omitempty"`

	// SAML federation
	SAMLEntityID    string `json:"saml_entity_id,omitempty"`
	SAMLSSOURL      string `json:"saml_sso_url,omitempty"`
	SAMLCertificate string `json:"saml_certificate,omitempty"`

	// Kerberos
	KerberosEnabled bool   `json:"kerberos_enabled"`
	KerberosRealm   string `json:"kerberos_realm,omitempty"`

	// SCIM provisioning
	SCIMEnabled  bool   `json:"scim_enabled"`
	SCIMEndpoint string `json:"scim_endpoint,omitempty"`

	// Attribute mapping (IdP claim → unified attribute)
	AttributeMap map[string]string `json:"attribute_map,omitempty"`
	GroupMap     map[string]string `json:"group_map,omitempty"`
}

// ─── Token Exchange Request / Response ──────────────────────────────

type TokenExchangeRequest struct {
	GrantType     string                 `json:"grant_type"`    // urn:ietf:params:oauth:grant-type:token-exchange
	SubjectToken  string                 `json:"subject_token"` // IdP-issued token
	SubjectType   string                 `json:"subject_type"`  // urn:ietf:params:oauth:token-type:id_token
	IdPID         string                 `json:"idp_id"`        // which IdP issued it
	DevicePosture map[string]interface{} `json:"device_posture,omitempty"`
}

type TokenExchangeResponse struct {
	AccessToken string          `json:"access_token"`
	TokenType   string          `json:"token_type"`
	ExpiresIn   int             `json:"expires_in"`
	Identity    UnifiedIdentity `json:"identity"`
}

// ─── Broker ─────────────────────────────────────────────────────────

// jwksCache holds fetched JWKS keys for an IdP.
type jwksCache struct {
	Keys      []jwkKey
	FetchedAt time.Time
}

type jwkKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

// Broker is the identity normalization layer that federates external
// IdPs and produces unified identity context for SGT policy evaluation.
type Broker struct {
	mu         sync.RWMutex
	idps       map[string]*IdPConfig       // id → config
	sessions   map[string]*UnifiedIdentity // session_id → identity
	jwks       map[string]*jwksCache       // idp_id → cached JWKS
	logger     *zap.Logger
	httpClient *http.Client
	idpStore   IdPPersister // optional DB persistence
}

// IdPPersister abstracts the DB store so broker stays testable without a database.
type IdPPersister interface {
	List(ctx context.Context) ([]IdPDBRecord, error)
	Upsert(ctx context.Context, r *IdPDBRecord) error
	Delete(ctx context.Context, id string) error
}

// IdPDBRecord mirrors the DB row (avoids circular import with db package).
type IdPDBRecord struct {
	ID              string
	OrgID           string
	Name            string
	ProviderType    string
	Enabled         bool
	IsDefault       bool
	ClientID        string
	ClientSecret    string
	IssuerURL       string
	JWKSURI         string
	TokenEndpoint   string
	Scopes          []string
	SAMLEntityID    string
	SAMLSSOURL      string
	SAMLCertificate string
	KerberosEnabled bool
	KerberosRealm   string
	SCIMEnabled     bool
	SCIMEndpoint    string
	AttributeMap    map[string]string
	GroupMap        map[string]string
}

func NewBroker(logger *zap.Logger) *Broker {
	b := &Broker{
		idps:       make(map[string]*IdPConfig),
		sessions:   make(map[string]*UnifiedIdentity),
		jwks:       make(map[string]*jwksCache),
		logger:     logger,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
	b.loadDefaults()
	return b
}

// SetPersister attaches a DB-backed persister and loads IdPs from it.
// IdPs loaded from DB override in-memory defaults with the same ID.
func (b *Broker) SetPersister(p IdPPersister) {
	b.idpStore = p
	if err := b.loadFromDB(); err != nil {
		b.logger.Error("Failed to load IdPs from database — using in-memory defaults", zap.Error(err))
	}
}

func (b *Broker) loadFromDB() error {
	if b.idpStore == nil {
		return nil
	}
	records, err := b.idpStore.List(context.Background())
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range records {
		r := &records[i]
		cfg := dbRecordToIdPConfig(r)
		b.idps[cfg.ID] = cfg
	}
	b.logger.Info("IdPs loaded from database", zap.Int("count", len(records)))
	return nil
}

func dbRecordToIdPConfig(r *IdPDBRecord) *IdPConfig {
	return &IdPConfig{
		ID: r.ID, OrgID: r.OrgID, Name: r.Name,
		ProviderType: r.ProviderType, Enabled: r.Enabled, IsDefault: r.IsDefault,
		ClientID: r.ClientID, ClientSecret: r.ClientSecret,
		IssuerURL: r.IssuerURL, JWKSURI: r.JWKSURI,
		TokenEndpoint: r.TokenEndpoint, Scopes: r.Scopes,
		SAMLEntityID: r.SAMLEntityID, SAMLSSOURL: r.SAMLSSOURL,
		SAMLCertificate: r.SAMLCertificate,
		KerberosEnabled: r.KerberosEnabled, KerberosRealm: r.KerberosRealm,
		SCIMEnabled: r.SCIMEnabled, SCIMEndpoint: r.SCIMEndpoint,
		AttributeMap: r.AttributeMap, GroupMap: r.GroupMap,
	}
}

func idpConfigToDBRecord(cfg *IdPConfig) *IdPDBRecord {
	return &IdPDBRecord{
		ID: cfg.ID, OrgID: cfg.OrgID, Name: cfg.Name,
		ProviderType: cfg.ProviderType, Enabled: cfg.Enabled, IsDefault: cfg.IsDefault,
		ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
		IssuerURL: cfg.IssuerURL, JWKSURI: cfg.JWKSURI,
		TokenEndpoint: cfg.TokenEndpoint, Scopes: cfg.Scopes,
		SAMLEntityID: cfg.SAMLEntityID, SAMLSSOURL: cfg.SAMLSSOURL,
		SAMLCertificate: cfg.SAMLCertificate,
		KerberosEnabled: cfg.KerberosEnabled, KerberosRealm: cfg.KerberosRealm,
		SCIMEnabled: cfg.SCIMEnabled, SCIMEndpoint: cfg.SCIMEndpoint,
		AttributeMap: cfg.AttributeMap, GroupMap: cfg.GroupMap,
	}
}

func (b *Broker) loadDefaults() {
	defaults := []IdPConfig{
		{
			ID: "okta-default", Name: "Okta (Primary)", ProviderType: "okta",
			Enabled: true, IsDefault: true,
			IssuerURL: "https://dev-12345.okta.com/oauth2/default",
			JWKSURI:   "https://dev-12345.okta.com/oauth2/default/v1/keys",
			Scopes:    []string{"openid", "profile", "email", "groups"},
			AttributeMap: map[string]string{
				"sub": "user_id", "email": "email", "name": "display_name",
				"groups": "groups", "department": "department",
			},
			SCIMEnabled: true,
		},
		{
			ID: "azure-ad", Name: "Microsoft Entra ID", ProviderType: "azure_ad",
			Enabled:         true,
			IssuerURL:       "https://login.microsoftonline.com/{tenant}/v2.0",
			JWKSURI:         "https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys",
			Scopes:          []string{"openid", "profile", "email", "User.Read", "GroupMember.Read.All"},
			KerberosEnabled: true, KerberosRealm: "CORP.EXAMPLE.COM",
			AttributeMap: map[string]string{
				"oid": "user_id", "preferred_username": "email",
				"name": "display_name", "groups": "groups",
				"jobTitle": "title", "department": "department",
			},
			SCIMEnabled:  true,
			SCIMEndpoint: "https://graph.microsoft.com/v1.0/",
		},
		{
			ID: "saml-generic", Name: "SAML Enterprise IdP", ProviderType: "saml",
			Enabled:      false,
			SAMLEntityID: "https://auth.apexaegis.io/saml/metadata",
			AttributeMap: map[string]string{
				"urn:oid:0.9.2342.19200300.100.1.1": "user_id",
				"urn:oid:0.9.2342.19200300.100.1.3": "email",
				"urn:oid:2.5.4.3":                   "display_name",
				"urn:oid:1.3.6.1.4.1.5923.1.1.1.7":  "groups",
			},
		},
		{
			ID: "ping-identity", Name: "Ping Identity (PingOne)", ProviderType: "ping",
			Enabled:   false,
			IssuerURL: "https://auth.pingone.com/{envId}/as",
			Scopes:    []string{"openid", "profile", "email"},
			AttributeMap: map[string]string{
				"sub": "user_id", "email": "email", "name": "display_name",
			},
		},
		{
			ID: "ldap-corp", Name: "Corporate LDAP/AD", ProviderType: "ldap",
			Enabled:         false,
			KerberosEnabled: true, KerberosRealm: "CORP.LOCAL",
			AttributeMap: map[string]string{
				"sAMAccountName": "user_id", "mail": "email",
				"displayName": "display_name", "memberOf": "groups",
				"department": "department", "title": "title",
			},
		},
	}
	for i := range defaults {
		b.idps[defaults[i].ID] = &defaults[i]
	}
}

// ── IdP CRUD ────────────────────────────────────────────────────────

func (b *Broker) ListIdPs() []IdPConfig {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make([]IdPConfig, 0, len(b.idps))
	for _, idp := range b.idps {
		copy := *idp
		copy.ClientSecret = "" // never expose secrets in list responses
		result = append(result, copy)
	}
	return result
}

func (b *Broker) GetIdP(id string) (*IdPConfig, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	idp, ok := b.idps[id]
	if !ok {
		return nil, false
	}
	copy := *idp
	copy.ClientSecret = "" // never expose secrets
	return &copy, true
}

func (b *Broker) CreateIdP(cfg *IdPConfig) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if cfg.ID == "" {
		raw := make([]byte, 8)
		rand.Read(raw)
		cfg.ID = "idp-" + hex.EncodeToString(raw)
	}
	b.idps[cfg.ID] = cfg
	b.logger.Info("IdP created",
		zap.String("id", cfg.ID),
		zap.String("name", cfg.Name),
		zap.String("type", cfg.ProviderType),
	)
	// Persist to DB asynchronously (best-effort — in-memory is authoritative)
	if b.idpStore != nil {
		go func() {
			if err := b.idpStore.Upsert(context.Background(), idpConfigToDBRecord(cfg)); err != nil {
				b.logger.Error("Failed to persist IdP to database", zap.String("id", cfg.ID), zap.Error(err))
			}
		}()
	}
	return cfg.ID
}

func (b *Broker) UpdateIdP(cfg *IdPConfig) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	existing, ok := b.idps[cfg.ID]
	if !ok {
		return false
	}
	// Preserve the existing client_secret when the update omits it
	// (the API never returns secrets, so UI updates send it empty).
	if cfg.ClientSecret == "" && existing.ClientSecret != "" {
		cfg.ClientSecret = existing.ClientSecret
	}
	b.idps[cfg.ID] = cfg
	if b.idpStore != nil {
		go func() {
			if err := b.idpStore.Upsert(context.Background(), idpConfigToDBRecord(cfg)); err != nil {
				b.logger.Error("Failed to persist IdP update", zap.String("id", cfg.ID), zap.Error(err))
			}
		}()
	}
	return true
}

func (b *Broker) DeleteIdP(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.idps[id]; !ok {
		return false
	}
	delete(b.idps, id)
	if b.idpStore != nil {
		go func() {
			if err := b.idpStore.Delete(context.Background(), id); err != nil {
				b.logger.Error("Failed to delete IdP from database", zap.String("id", id), zap.Error(err))
			}
		}()
	}
	return true
}

// ── Token Exchange (RFC 8693) ───────────────────────────────────────

// ExchangeToken receives an external IdP token (OIDC id_token, SAML
// assertion, or Kerberos ticket), validates it against the configured
// IdP, normalizes the claims into a UnifiedIdentity, and issues an
// internal ApexAegis access token. This is the core broker operation.
func (b *Broker) ExchangeToken(_ context.Context, req TokenExchangeRequest) (*TokenExchangeResponse, error) {
	b.mu.RLock()
	idp, ok := b.idps[req.IdPID]
	b.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown IdP: %s", req.IdPID)
	}
	if !idp.Enabled {
		return nil, fmt.Errorf("IdP %s is disabled", idp.Name)
	}

	// Step 1: Validate external token against IdP JWKS/cert
	claims, err := b.validateExternalToken(idp, req.SubjectToken, req.SubjectType)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// Step 2: Map external claims → UnifiedIdentity
	identity := b.mapClaims(idp, claims)

	// Step 3: Enrich with device posture
	if req.DevicePosture != nil {
		b.enrichDevicePosture(&identity, req.DevicePosture)
	}

	// Step 4: Compute risk score
	identity.RiskScore = b.computeRiskScore(&identity)
	identity.ComplianceState = b.assessCompliance(&identity)

	// Step 5: Resolve SGT assignments based on identity context
	identity.EffectiveSGTs = b.resolveSGTs(&identity)

	// Step 6: Store session
	raw := make([]byte, 16)
	rand.Read(raw)
	identity.SessionID = hex.EncodeToString(raw)
	identity.Timestamp = time.Now().UTC()

	b.mu.Lock()
	b.sessions[identity.SessionID] = &identity
	b.mu.Unlock()

	b.logger.Info("Token exchanged",
		zap.String("session_id", identity.SessionID),
		zap.String("user", identity.Identity.Email),
		zap.String("idp", idp.Name),
		zap.Int("risk_score", identity.RiskScore),
		zap.String("compliance", identity.ComplianceState),
	)

	return &TokenExchangeResponse{
		AccessToken: "aegis_at_" + identity.SessionID,
		TokenType:   "Bearer",
		ExpiresIn:   900, // 15m
		Identity:    identity,
	}, nil
}

// GetSession retrieves a live session's unified identity context.
func (b *Broker) GetSession(sessionID string) (*UnifiedIdentity, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	s, ok := b.sessions[sessionID]
	if !ok {
		return nil, false
	}
	copy := *s
	return &copy, true
}

// ListSessions returns all active sessions (admin use).
func (b *Broker) ListSessions() []UnifiedIdentity {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make([]UnifiedIdentity, 0, len(b.sessions))
	for _, s := range b.sessions {
		result = append(result, *s)
	}
	return result
}

// RevokeSession removes a session.
func (b *Broker) RevokeSession(sessionID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.sessions[sessionID]; !ok {
		return false
	}
	delete(b.sessions, sessionID)
	return true
}

// ── Internal helpers ────────────────────────────────────────────────

func (b *Broker) validateExternalToken(idp *IdPConfig, token, tokenType string) (map[string]interface{}, error) {
	_ = tokenType
	return b.ValidateOIDCToken(idp, token)
}

// ValidateOIDCToken validates a JWT token against the IdP's JWKS (RS256/RS384/RS512).
// Falls back to unverified parse in dev/test mode if JWKS is unavailable.
func (b *Broker) ValidateOIDCToken(idp *IdPConfig, tokenStr string) (map[string]interface{}, error) {
	// Resolve JWKS URI
	jwksURI := idp.JWKSURI
	if jwksURI == "" && idp.IssuerURL != "" {
		jwksURI = idp.IssuerURL + "/v1/keys"
	}

	// Fetch/cache JWKS
	keys, err := b.getJWKS(idp.ID, jwksURI)
	if err != nil {
		b.logger.Error("JWKS fetch failed — cannot validate token",
			zap.String("idp", idp.Name), zap.Error(err))
		return nil, fmt.Errorf("JWKS unavailable for %s: %w", idp.Name, err)
	}

	// Parse and verify the JWT
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		// Only accept RSA signing methods
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		kid, _ := t.Header["kid"].(string)
		for _, k := range keys {
			if k.Kid == kid && k.Kty == "RSA" {
				return rsaPublicKeyFromJWK(k)
			}
		}
		// If no kid match, try first RSA key
		for _, k := range keys {
			if k.Kty == "RSA" {
				return rsaPublicKeyFromJWK(k)
			}
		}
		return nil, fmt.Errorf("no matching key found for kid=%s", kid)
	}, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}))

	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Validate issuer if configured
	if idp.IssuerURL != "" {
		iss, _ := claims["iss"].(string)
		if iss != idp.IssuerURL {
			return nil, fmt.Errorf("issuer mismatch: got %s, expected %s", iss, idp.IssuerURL)
		}
	}

	// Validate audience if client_id is set
	if idp.ClientID != "" {
		aud := extractAudience(claims)
		if !containsStr(aud, idp.ClientID) {
			return nil, fmt.Errorf("audience mismatch: token not issued for client %s", idp.ClientID)
		}
	}

	b.logger.Debug("OIDC token validated",
		zap.String("idp", idp.Name),
		zap.String("subject", claimString(claims, "sub")),
		zap.String("email", claimString(claims, "email")),
	)

	return map[string]interface{}(claims), nil
}

// GetIdPClientSecret returns the client secret for an IdP (kept separate so
// it is never serialized in ListIdPs responses).
func (b *Broker) GetIdPClientSecret(idpID string) string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	idp, ok := b.idps[idpID]
	if !ok {
		return ""
	}
	return idp.ClientSecret
}

func (b *Broker) getJWKS(idpID, jwksURI string) ([]jwkKey, error) {
	if jwksURI == "" {
		return nil, fmt.Errorf("no JWKS URI configured")
	}

	b.mu.RLock()
	cached, ok := b.jwks[idpID]
	b.mu.RUnlock()

	// Cache valid for 1 hour
	if ok && time.Since(cached.FetchedAt) < time.Hour {
		return cached.Keys, nil
	}

	resp, err := b.httpClient.Get(jwksURI)
	if err != nil {
		// Return cached keys if available
		if ok {
			return cached.Keys, nil
		}
		return nil, fmt.Errorf("JWKS fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if ok {
			return cached.Keys, nil
		}
		return nil, fmt.Errorf("JWKS endpoint returned %d: %s", resp.StatusCode, body)
	}

	var jwksResp jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwksResp); err != nil {
		return nil, fmt.Errorf("invalid JWKS response: %w", err)
	}

	b.mu.Lock()
	b.jwks[idpID] = &jwksCache{Keys: jwksResp.Keys, FetchedAt: time.Now()}
	b.mu.Unlock()

	b.logger.Info("JWKS refreshed", zap.String("idp_id", idpID), zap.Int("key_count", len(jwksResp.Keys)))
	return jwksResp.Keys, nil
}

func rsaPublicKeyFromJWK(k jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("invalid JWK modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("invalid JWK exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func extractAudience(claims jwt.MapClaims) []string {
	switch v := claims["aud"].(type) {
	case string:
		return []string{v}
	case []interface{}:
		var aud []string
		for _, a := range v {
			if s, ok := a.(string); ok {
				aud = append(aud, s)
			}
		}
		return aud
	}
	return nil
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func claimString(claims jwt.MapClaims, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

func (b *Broker) mapClaims(idp *IdPConfig, claims map[string]interface{}) UnifiedIdentity {
	identity := UnifiedIdentity{
		OrgID: idp.OrgID,
		Identity: IdentityDomain{
			IdPSource:  idp.ProviderType,
			Attributes: make(map[string]string),
		},
		Time: TimeDomain{
			LocalTime:     time.Now(),
			UTC:           time.Now().UTC(),
			BusinessHours: isBusinessHours(time.Now()),
		},
	}

	// Apply attribute mapping
	for externalKey, internalField := range idp.AttributeMap {
		val, ok := claims[externalKey]
		if !ok {
			continue
		}
		switch internalField {
		case "user_id":
			identity.Identity.UserID = fmt.Sprintf("%v", val)
		case "email":
			identity.Identity.Email = fmt.Sprintf("%v", val)
		case "display_name":
			identity.Identity.DisplayName = fmt.Sprintf("%v", val)
		case "department":
			identity.Identity.Department = fmt.Sprintf("%v", val)
		case "title":
			identity.Identity.Title = fmt.Sprintf("%v", val)
		case "groups":
			if groups, ok := val.([]interface{}); ok {
				for _, g := range groups {
					identity.Identity.Groups = append(identity.Identity.Groups, fmt.Sprintf("%v", g))
				}
			}
		default:
			identity.Identity.Attributes[internalField] = fmt.Sprintf("%v", val)
		}
	}

	// Check MFA from amr claim
	if amr, ok := claims["amr"].([]interface{}); ok {
		for _, m := range amr {
			if fmt.Sprintf("%v", m) == "mfa" {
				identity.Identity.MFAVerified = true
			}
		}
	}

	return identity
}

func (b *Broker) enrichDevicePosture(id *UnifiedIdentity, posture map[string]interface{}) {
	if v, ok := posture["device_id"].(string); ok {
		id.Device.DeviceID = v
	}
	if v, ok := posture["hostname"].(string); ok {
		id.Device.Hostname = v
	}
	if v, ok := posture["os"].(string); ok {
		id.Device.OS = v
	}
	if v, ok := posture["os_version"].(string); ok {
		id.Device.OSVersion = v
	}
	if v, ok := posture["managed"].(bool); ok {
		id.Device.Managed = v
	}
	if v, ok := posture["compliant"].(bool); ok {
		id.Device.Compliant = v
	}
	if v, ok := posture["disk_encrypted"].(bool); ok {
		id.Device.DiskEncrypted = v
	}
	if v, ok := posture["firewall_active"].(bool); ok {
		id.Device.FirewallActive = v
	}
	if v, ok := posture["antivirus_ok"].(bool); ok {
		id.Device.AntivirusOK = v
	}
	if v, ok := posture["domain_joined"].(bool); ok {
		id.Device.DomainJoined = v
	}
	if v, ok := posture["entra_joined"].(bool); ok {
		id.Device.EntraJoined = v
	}
	if v, ok := posture["cert_valid"].(bool); ok {
		id.Device.CertValid = v
	}
}

func (b *Broker) computeRiskScore(id *UnifiedIdentity) int {
	score := 0

	// Identity risk factors
	if !id.Identity.MFAVerified {
		score += 25
	}
	if id.Identity.RiskLevel == "high" {
		score += 30
	} else if id.Identity.RiskLevel == "critical" {
		score += 50
	}

	// Device risk factors
	if !id.Device.Managed {
		score += 15
	}
	if !id.Device.Compliant {
		score += 10
	}
	if !id.Device.DiskEncrypted {
		score += 10
	}
	if !id.Device.FirewallActive {
		score += 5
	}
	if !id.Device.AntivirusOK {
		score += 10
	}
	if id.Device.JailBroken {
		score += 40
	}

	// Location risk factors
	if id.Location.TorDetected {
		score += 40
	}
	if id.Location.ProxyDetected {
		score += 15
	}
	if !id.Location.TrustedNet {
		score += 5
	}

	// Time risk factors
	if !id.Time.BusinessHours {
		score += 5
	}

	// Data risk
	if id.Data.DLPTriggered {
		score += 20
	}

	if score > 100 {
		score = 100
	}
	return score
}

func (b *Broker) assessCompliance(id *UnifiedIdentity) string {
	if id.Device.JailBroken || id.Location.TorDetected {
		return "non_compliant"
	}
	if !id.Identity.MFAVerified {
		return "non_compliant"
	}
	if id.Device.Managed && id.Device.Compliant && id.Device.DiskEncrypted &&
		id.Device.FirewallActive && id.Device.AntivirusOK {
		return "compliant"
	}
	if id.Device.DeviceID != "" {
		return "non_compliant"
	}
	return "unknown"
}

func (b *Broker) resolveSGTs(id *UnifiedIdentity) []int {
	// In production: evaluate SGT classification rules against
	// all 6 domains. Placeholder: assign based on group membership.
	sgts := []int{}
	for _, group := range id.Identity.Groups {
		switch group {
		case "security-admins", "network-ops":
			sgts = append(sgts, 999) // Management
		case "soc-team":
			sgts = append(sgts, 800) // SOC
		case "developers":
			sgts = append(sgts, 200) // Development
		case "finance":
			sgts = append(sgts, 500) // Finance
		default:
			sgts = append(sgts, 10) // Corporate Users
		}
	}
	return sgts
}

func isBusinessHours(t time.Time) bool {
	h := t.Hour()
	wd := t.Weekday()
	return wd >= time.Monday && wd <= time.Friday && h >= 8 && h < 18
}
