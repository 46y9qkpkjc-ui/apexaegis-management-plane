// Package dot1x provides an HTTPS-based 802.1X authenticator that replaces
// traditional RADIUS for LAN authentication. Instead of UDP-based RADIUS,
// the supplicant (or the switch acting on its behalf) talks to an HTTPS
// endpoint. This integrates with the management plane's identity providers
// and supports EAP-TLS, EAP-TTLS, and PEAP via REST API.
//
// The AAA (Authentication, Authorization, Accounting) service runs as an
// HTTPS server that SDN whitebox switches call into for:
//   - /api/v1/dot1x/authenticate    — EAP/credentials validation
//   - /api/v1/dot1x/authorize       — VLAN/segment assignment
//   - /api/v1/dot1x/accounting      — session start/stop/interim
//   - /api/v1/dot1x/mac-auth        — MAC Authentication Bypass (MAB)
package dot1x

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// EAPMethod defines supported EAP authentication methods.
type EAPMethod string

const (
	EAPTLS  EAPMethod = "EAP-TLS"
	EAPTTLS EAPMethod = "EAP-TTLS"
	PEAP    EAPMethod = "PEAP"
	MABEAP  EAPMethod = "MAB" // MAC Authentication Bypass
)

// AuthResult is the outcome of a Dot1X authentication attempt.
type AuthResult string

const (
	AuthSuccess   AuthResult = "success"
	AuthReject    AuthResult = "reject"
	AuthChallenge AuthResult = "challenge" // additional factor needed
)

// AuthRequest is sent by the switch/supplicant to authenticate a device.
type AuthRequest struct {
	SwitchID      string    `json:"switch_id"`
	PortID        string    `json:"port_id"`
	MACAddress    string    `json:"mac_address"`
	EAPMethod     EAPMethod `json:"eap_method"`
	Username      string    `json:"username,omitempty"`
	Password      string    `json:"password,omitempty"`        // for PEAP/EAP-TTLS inner auth
	ClientCertPEM string    `json:"client_cert_pem,omitempty"` // for EAP-TLS
	NASIdentifier string    `json:"nas_identifier,omitempty"`
	CalledStation string    `json:"called_station,omitempty"`
	OrgID         string    `json:"org_id"`
}

// AuthResponse tells the switch what to do with the port.
type AuthResponse struct {
	Result         AuthResult        `json:"result"`
	SessionID      string            `json:"session_id,omitempty"`
	Username       string            `json:"username,omitempty"`
	AssignedVLAN   int               `json:"assigned_vlan,omitempty"`
	SegmentGroup   string            `json:"segment_group,omitempty"`
	ACLName        string            `json:"acl_name,omitempty"`
	SessionTimeout int               `json:"session_timeout,omitempty"` // seconds
	ReauthPeriod   int               `json:"reauth_period,omitempty"`   // seconds
	Message        string            `json:"message,omitempty"`
	Attributes     map[string]string `json:"attributes,omitempty"`
}

// AuthzRequest asks what access level a device should get.
type AuthzRequest struct {
	SessionID  string `json:"session_id"`
	SwitchID   string `json:"switch_id"`
	PortID     string `json:"port_id"`
	MACAddress string `json:"mac_address"`
	Username   string `json:"username"`
	DeviceType string `json:"device_type,omitempty"`
	OrgID      string `json:"org_id"`
}

// AuthzResponse specifies the policy to apply.
type AuthzResponse struct {
	Allowed      bool   `json:"allowed"`
	VLAN         int    `json:"vlan"`
	SegmentGroup string `json:"segment_group"`
	ACLName      string `json:"acl_name,omitempty"`
	QoSPolicy    string `json:"qos_policy,omitempty"`
	MaxBandwidth int    `json:"max_bandwidth_kbps,omitempty"`
	Message      string `json:"message,omitempty"`
}

// AcctRequest records session accounting events.
type AcctRequest struct {
	SessionID   string `json:"session_id"`
	Type        string `json:"type"` // start, stop, interim-update
	SwitchID    string `json:"switch_id"`
	PortID      string `json:"port_id"`
	MACAddress  string `json:"mac_address"`
	Username    string `json:"username"`
	InputBytes  int64  `json:"input_bytes,omitempty"`
	OutputBytes int64  `json:"output_bytes,omitempty"`
	Duration    int    `json:"session_duration,omitempty"` // seconds
	Reason      string `json:"terminate_reason,omitempty"`
	OrgID       string `json:"org_id"`
}

// Session represents an active Dot1X authenticated session.
type Session struct {
	ID           string    `json:"id"`
	SwitchID     string    `json:"switch_id"`
	PortID       string    `json:"port_id"`
	MACAddress   string    `json:"mac_address"`
	Username     string    `json:"username"`
	EAPMethod    EAPMethod `json:"eap_method"`
	VLAN         int       `json:"vlan"`
	SegmentGroup string    `json:"segment_group"`
	State        string    `json:"state"` // authenticated, reauthenticating, disconnected
	StartedAt    time.Time `json:"started_at"`
	LastActivity time.Time `json:"last_activity"`
	InputBytes   int64     `json:"input_bytes"`
	OutputBytes  int64     `json:"output_bytes"`
	OrgID        string    `json:"org_id"`
}

// MACAuthEntry for MAC Authentication Bypass (MAB) — known devices
// that bypass full EAP and get access based on MAC address alone.
type MACAuthEntry struct {
	MACAddress   string    `json:"mac_address"`
	DeviceName   string    `json:"device_name"`
	DeviceType   string    `json:"device_type"` // printer, camera, iot, voip
	VLAN         int       `json:"vlan"`
	SegmentGroup string    `json:"segment_group"`
	OrgID        string    `json:"org_id"`
	CreatedAt    time.Time `json:"created_at"`
}

// Authenticator is the HTTPS-based 802.1X authentication engine.
type Authenticator struct {
	mu       sync.RWMutex
	sessions map[string]*Session      // session_id -> session
	macDB    map[string]*MACAuthEntry // normalized_mac -> entry
	users    UserStore                // pluggable identity backend
	logger   *zap.Logger
}

// UserStore is the interface the authenticator uses to validate credentials.
// Implemented by the management plane's identity provider.
type UserStore interface {
	ValidateCredentials(username, password, orgID string) (bool, error)
	GetUserGroups(username, orgID string) ([]string, error)
}

// NewAuthenticator creates a new HTTPS-based Dot1X authenticator.
func NewAuthenticator(users UserStore, logger *zap.Logger) *Authenticator {
	return &Authenticator{
		sessions: make(map[string]*Session),
		macDB:    make(map[string]*MACAuthEntry),
		users:    users,
		logger:   logger,
	}
}

// Authenticate processes an EAP authentication request.
func (a *Authenticator) Authenticate(req AuthRequest) AuthResponse {
	a.logger.Info("Dot1X auth attempt",
		zap.String("switch", req.SwitchID),
		zap.String("port", req.PortID),
		zap.String("mac", req.MACAddress),
		zap.String("method", string(req.EAPMethod)),
	)

	switch req.EAPMethod {
	case EAPTLS:
		return a.authenticateEAPTLS(req)
	case EAPTTLS, PEAP:
		return a.authenticatePassword(req)
	case MABEAP:
		return a.authenticateMAB(req)
	default:
		return AuthResponse{
			Result:  AuthReject,
			Message: "Unsupported EAP method",
		}
	}
}

// Authorize determines the access policy for an authenticated session.
func (a *Authenticator) Authorize(req AuthzRequest) AuthzResponse {
	a.mu.RLock()
	sess, ok := a.sessions[req.SessionID]
	a.mu.RUnlock()

	if !ok {
		return AuthzResponse{Allowed: false, Message: "Session not found"}
	}

	// Get user groups for policy lookup
	groups, err := a.users.GetUserGroups(req.Username, req.OrgID)
	if err != nil {
		a.logger.Warn("Failed to get user groups for authz",
			zap.String("user", req.Username),
			zap.Error(err),
		)
	}

	resp := AuthzResponse{
		Allowed:      true,
		VLAN:         sess.VLAN,
		SegmentGroup: sess.SegmentGroup,
	}

	// Apply group-based policies
	for _, g := range groups {
		switch g {
		case "network-admins":
			resp.ACLName = "full-access"
		case "contractors":
			resp.ACLName = "restricted"
			resp.MaxBandwidth = 10000 // 10 Mbps
		case "iot-devices":
			resp.ACLName = "iot-restricted"
			resp.MaxBandwidth = 5000 // 5 Mbps
		}
	}

	return resp
}

// RecordAccounting processes session accounting updates.
func (a *Authenticator) RecordAccounting(req AcctRequest) {
	a.mu.Lock()
	defer a.mu.Unlock()

	sess, ok := a.sessions[req.SessionID]
	if !ok {
		a.logger.Debug("Accounting for unknown session", zap.String("session", req.SessionID))
		return
	}

	switch req.Type {
	case "start":
		sess.State = "authenticated"
		sess.StartedAt = time.Now().UTC()
	case "interim-update":
		sess.InputBytes = req.InputBytes
		sess.OutputBytes = req.OutputBytes
		sess.LastActivity = time.Now().UTC()
	case "stop":
		sess.State = "disconnected"
		sess.InputBytes = req.InputBytes
		sess.OutputBytes = req.OutputBytes
		a.logger.Info("Dot1X session ended",
			zap.String("session", req.SessionID),
			zap.String("user", req.Username),
			zap.String("reason", req.Reason),
			zap.Int64("in_bytes", req.InputBytes),
			zap.Int64("out_bytes", req.OutputBytes),
		)
	}
}

// ListSessions returns all active sessions, optionally filtered by org.
func (a *Authenticator) ListSessions(orgID string) []Session {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var out []Session
	for _, s := range a.sessions {
		if orgID != "" && s.OrgID != orgID {
			continue
		}
		out = append(out, *s)
	}
	return out
}

// GetSession returns a single session by ID.
func (a *Authenticator) GetSession(id string) (*Session, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	s, ok := a.sessions[id]
	if !ok {
		return nil, false
	}
	cp := *s
	return &cp, true
}

// DisconnectSession forces a session to end (CoA — Change of Authorization).
func (a *Authenticator) DisconnectSession(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[id]
	if !ok {
		return false
	}
	s.State = "disconnected"
	a.logger.Info("Session force-disconnected", zap.String("session", id))
	return true
}

// ── MAB (MAC Authentication Bypass) ──────────────────────────────────

// RegisterMAC adds a MAC address to the MAB whitelist.
func (a *Authenticator) RegisterMAC(entry MACAuthEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry.MACAddress = normalizeMAC(entry.MACAddress)
	entry.CreatedAt = time.Now().UTC()
	a.macDB[entry.MACAddress] = &entry
}

// RemoveMAC removes a MAC from the MAB whitelist.
func (a *Authenticator) RemoveMAC(mac string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	mac = normalizeMAC(mac)
	if _, ok := a.macDB[mac]; !ok {
		return false
	}
	delete(a.macDB, mac)
	return true
}

// ListMACs returns all registered MAB entries.
func (a *Authenticator) ListMACs(orgID string) []MACAuthEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]MACAuthEntry, 0)
	for _, e := range a.macDB {
		if orgID != "" && e.OrgID != orgID {
			continue
		}
		out = append(out, *e)
	}
	return out
}

// ── Internal EAP handlers ──────────────────────────────────────────

func (a *Authenticator) authenticateEAPTLS(req AuthRequest) AuthResponse {
	if req.ClientCertPEM == "" {
		return AuthResponse{Result: AuthReject, Message: "Client certificate required for EAP-TLS"}
	}

	block, _ := pem.Decode([]byte(req.ClientCertPEM))
	if block == nil {
		return AuthResponse{Result: AuthReject, Message: "Invalid certificate format"}
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return AuthResponse{Result: AuthReject, Message: "Certificate parse failed"}
	}

	// Validate certificate is not expired
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return AuthResponse{Result: AuthReject, Message: "Certificate expired or not yet valid"}
	}

	username := cert.Subject.CommonName
	if username == "" {
		return AuthResponse{Result: AuthReject, Message: "Certificate has no Common Name"}
	}

	return a.createSession(req, username)
}

func (a *Authenticator) authenticatePassword(req AuthRequest) AuthResponse {
	if req.Username == "" || req.Password == "" {
		return AuthResponse{Result: AuthReject, Message: "Username and password required"}
	}

	valid, err := a.users.ValidateCredentials(req.Username, req.Password, req.OrgID)
	if err != nil {
		a.logger.Error("Credential validation error",
			zap.String("user", req.Username),
			zap.Error(err),
		)
		return AuthResponse{Result: AuthReject, Message: "Authentication service error"}
	}

	if !valid {
		return AuthResponse{Result: AuthReject, Message: "Invalid credentials"}
	}

	return a.createSession(req, req.Username)
}

func (a *Authenticator) authenticateMAB(req AuthRequest) AuthResponse {
	mac := normalizeMAC(req.MACAddress)

	a.mu.RLock()
	entry, ok := a.macDB[mac]
	a.mu.RUnlock()

	if !ok {
		return AuthResponse{Result: AuthReject, Message: "MAC address not in whitelist"}
	}

	resp := a.createSession(req, "mab:"+entry.DeviceName)
	resp.AssignedVLAN = entry.VLAN
	resp.SegmentGroup = entry.SegmentGroup
	return resp
}

func (a *Authenticator) createSession(req AuthRequest, username string) AuthResponse {
	sessionID := fmt.Sprintf("dot1x-%s-%s-%d", req.SwitchID, req.PortID, time.Now().UnixMilli())

	sess := &Session{
		ID:           sessionID,
		SwitchID:     req.SwitchID,
		PortID:       req.PortID,
		MACAddress:   normalizeMAC(req.MACAddress),
		Username:     username,
		EAPMethod:    req.EAPMethod,
		VLAN:         100, // default — overridden by segment group rules
		SegmentGroup: "default",
		State:        "authenticated",
		StartedAt:    time.Now().UTC(),
		LastActivity: time.Now().UTC(),
		OrgID:        req.OrgID,
	}

	a.mu.Lock()
	a.sessions[sessionID] = sess
	a.mu.Unlock()

	a.logger.Info("Dot1X session created",
		zap.String("session", sessionID),
		zap.String("user", username),
		zap.String("switch", req.SwitchID),
		zap.String("port", req.PortID),
		zap.String("method", string(req.EAPMethod)),
	)

	return AuthResponse{
		Result:         AuthSuccess,
		SessionID:      sessionID,
		Username:       username,
		AssignedVLAN:   sess.VLAN,
		SegmentGroup:   sess.SegmentGroup,
		SessionTimeout: 28800, // 8 hours
		ReauthPeriod:   3600,  // 1 hour
		Message:        "Authenticated",
	}
}

// ── Helpers ─────────────────────────────────────────────────────────

func normalizeMAC(mac string) string {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return mac
	}
	return hw.String()
}
