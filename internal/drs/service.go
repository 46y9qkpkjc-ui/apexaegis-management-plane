// Package drs implements the Device Registration Service — ApexAegis's own
// Entra-like DRS for device identity issuance.
package drs

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Service is the Device Registration Service.
type Service struct {
	db       DRSPersister
	caURL    string // step-ca base URL
	caFP     string // step-ca root fingerprint
	oidcISS  string // OIDC issuer URL
	logger   *zap.Logger
}

// DRSPersister is the interface for DRS data storage.
type DRSPersister interface {
	CreateDevice(ctx context.Context, dev *DeviceDirectory) (*DeviceDirectory, error)
	GetDevice(ctx context.Context, orgID, deviceID string) (*DeviceDirectory, error)
	GetDeviceByFingerprint(ctx context.Context, fingerprint string) (*DeviceDirectory, error)
	UpdateDevice(ctx context.Context, dev *DeviceDirectory) error
	UpdateDeviceCert(ctx context.Context, orgID, deviceID, certSubject, certSerial, certFingerprint string, certNotAfter time.Time) error
	UpdateDevicePosture(ctx context.Context, orgID, deviceID string, managed, compliant, diskEncrypted, firewallActive bool) error
	DeleteDevice(ctx context.Context, orgID, deviceID string) error
	LogJoinEvent(ctx context.Context, deviceID, eventType, actor, actorID, fingerprint string, details map[string]interface{}) error
}

// DeviceDirectory represents a device in our directory (your "Entra ID").
type DeviceDirectory struct {
	ID                    string     `json:"id"`
	OrgID                 string     `json:"org_id"`
	DeviceID              string     `json:"device_id"`
	DisplayName           string     `json:"display_name"`
	OperatingSystem       string     `json:"operating_system"`
	OSVersion             string     `json:"os_version,omitempty"`
	JoinType              string     `json:"join_type"`
	JoinStatus            string     `json:"join_status"`
	CertSubject           string     `json:"cert_subject,omitempty"`
	CertSerial            string     `json:"cert_serial,omitempty"`
	CertFingerprintSHA256 string     `json:"cert_fingerprint_sha256,omitempty"`
	CertNotAfter          *time.Time `json:"cert_not_after,omitempty"`
	CertIssuer            string     `json:"cert_issuer,omitempty"`
	EntraDeviceID         string     `json:"entra_device_id,omitempty"`
	TenantID              string     `json:"tenant_id,omitempty"`
	OwnerUserID           string     `json:"owner_user_id,omitempty"`
	OwnerEmail            string     `json:"owner_email,omitempty"`
	Managed               bool       `json:"managed"`
	Compliant             bool       `json:"compliant"`
	DiskEncrypted         bool       `json:"disk_encrypted"`
	FirewallActive        bool       `json:"firewall_active"`
	LastPostureCheck      *time.Time `json:"last_posture_check,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
	LastSeen              *time.Time `json:"last_seen,omitempty"`
}

// RegisterRequest is the initial device registration request.
type RegisterRequest struct {
	DeviceName     string `json:"device_name"`
	OperatingSystem string `json:"os_type"`
	OSVersion      string `json:"os_version,omitempty"`
	CSRPEM         string `json:"csr_pem"`
}

// RegisterResponse is returned when a device code is generated.
type RegisterResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	Interval        int    `json:"interval"`
	ExpiresIn       int    `json:"expires_in"`
}

// PollResponse is the response to polling for user auth.
type PollResponse struct {
	Status      string `json:"status"`
	DeviceID    string `json:"device_id,omitempty"`
	Token       string `json:"token,omitempty"`
	CAURL       string `json:"ca_url,omitempty"`
	CAFingerprint string `json:"ca_fingerprint,omitempty"`
}

// CompleteResponse is returned after registration is finalized.
type CompleteResponse struct {
	DeviceJWT string `json:"device_jwt"`
	ExpiresAt string `json:"expires_at"`
	DeviceID  string `json:"device_id"`
}

// NewService creates a new DRS service.
func NewService(db DRSPersister, caURL, caFingerprint, oidcIssuer string, logger *zap.Logger) *Service {
	return &Service{
		db:      db,
		caURL:   caURL,
		caFP:    caFingerprint,
		oidcISS: oidcIssuer,
		logger:  logger,
	}
}

// Register initiates device registration. Returns a device code for user auth.
func (s *Service) Register(ctx context.Context, orgID string, req *RegisterRequest) (*RegisterResponse, error) {
	if req.DeviceName == "" || req.OperatingSystem == "" || req.CSRPEM == "" {
		return nil, errors.New("device_name, os_type, and csr_pem are required")
	}

	// Generate device code and user code
	deviceCode, userCode, err := generateCodes()
	if err != nil {
		return nil, fmt.Errorf("failed to generate codes: %w", err)
	}

	// Create pending device in directory
	dev := &DeviceDirectory{
		OrgID:           orgID,
		DeviceID:        userCode, // temporary — replaced with real ID after auth
		DisplayName:     req.DeviceName,
		OperatingSystem: req.OperatingSystem,
		OSVersion:       req.OSVersion,
		JoinType:        "registered",
		JoinStatus:      "pending",
		TenantID:        orgID,
	}

	if _, err := s.db.CreateDevice(ctx, dev); err != nil {
		return nil, fmt.Errorf("failed to create device: %w", err)
	}

	s.logger.Info("DRS registration initiated",
		zap.String("org_id", orgID),
		zap.String("device_name", req.DeviceName),
		zap.String("user_code", userCode),
	)

	return &RegisterResponse{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationURI: s.oidcISS + "/device?user_code=" + userCode,
		Interval:        5,
		ExpiresIn:       900,
	}, nil
}

// CompleteFinalize finalizes device registration after user auth and cert issuance.
func (s *Service) CompleteFinalize(ctx context.Context, orgID, deviceID, certFingerprint, certSerial string) (*CompleteResponse, error) {
	dev, err := s.db.GetDevice(ctx, orgID, deviceID)
	if err != nil {
		return nil, errors.New("device not found")
	}

	// Update device with cert info
	dev.JoinStatus = "active"
	dev.CertFingerprintSHA256 = certFingerprint
	dev.CertSerial = certSerial
	dev.CertIssuer = "step-ca"
	now := time.Now()
	dev.UpdatedAt = now
	dev.LastSeen = &now

	if err := s.db.UpdateDevice(ctx, dev); err != nil {
		return nil, fmt.Errorf("failed to update device: %w", err)
	}

	// Log join event
	s.db.LogJoinEvent(ctx, dev.ID, "join", "user", orgID, certFingerprint, nil)

	s.logger.Info("DRS device registered",
		zap.String("org_id", orgID),
		zap.String("device_id", deviceID),
		zap.String("fingerprint", certFingerprint),
	)

	// Generate device JWT (short-lived, used for initial auth)
	deviceJWT := generateDeviceJWT(dev, s.oidcISS)

	return &CompleteResponse{
		DeviceJWT: deviceJWT,
		ExpiresAt: now.Add(15 * time.Minute).Format(time.RFC3339),
		DeviceID:  dev.ID,
	}, nil
}

// GetDevice returns a device from the directory.
func (s *Service) GetDevice(ctx context.Context, orgID, deviceID string) (*DeviceDirectory, error) {
	return s.db.GetDevice(ctx, orgID, deviceID)
}

// GetDeviceByCert returns a device by its cert fingerprint.
func (s *Service) GetDeviceByCert(ctx context.Context, fingerprint string) (*DeviceDirectory, error) {
	return s.db.GetDeviceByFingerprint(ctx, fingerprint)
}

// RenewCert initiates certificate renewal for an existing device.
func (s *Service) RenewCert(ctx context.Context, orgID, deviceID string) (*PollResponse, error) {
	dev, err := s.db.GetDevice(ctx, orgID, deviceID)
	if err != nil {
		return nil, errors.New("device not found")
	}

	if dev.JoinStatus != "active" {
		return nil, errors.New("device is not active")
	}

	// Generate new device code for renewal
	deviceCode, _, err := generateCodes()
	if err != nil {
		return nil, fmt.Errorf("failed to generate renewal codes: %w", err)
	}

	return &PollResponse{
		Status:      "pending_renewal",
		DeviceID:    dev.ID,
		Token:       deviceCode,
		CAURL:       s.caURL,
		CAFingerprint: s.caFP,
	}, nil
}

// UpdatePosture updates device compliance posture.
func (s *Service) UpdatePosture(ctx context.Context, orgID, deviceID string, managed, compliant, diskEncrypted, firewallActive bool) error {
	if err := s.db.UpdateDevicePosture(ctx, orgID, deviceID, managed, compliant, diskEncrypted, firewallActive); err != nil {
		return err
	}

	s.logger.Info("device posture updated",
		zap.String("org_id", orgID),
		zap.String("device_id", deviceID),
		zap.Bool("managed", managed),
		zap.Bool("compliant", compliant),
	)

	return nil
}

// Deregister removes a device from the directory.
func (s *Service) Deregister(ctx context.Context, orgID, deviceID string) error {
	dev, err := s.db.GetDevice(ctx, orgID, deviceID)
	if err != nil {
		return errors.New("device not found")
	}

	dev.JoinStatus = "deleted"
	if err := s.db.UpdateDevice(ctx, dev); err != nil {
		return err
	}

	s.db.LogJoinEvent(ctx, dev.ID, "deregister", "admin", orgID, "", nil)
	return nil
}

// generateCodes generates a device code and a human-readable user code.
func generateCodes() (deviceCode, userCode string, err error) {
	dcBytes := make([]byte, 32)
	if _, err := rand.Read(dcBytes); err != nil {
		return "", "", err
	}
	deviceCode = base64.RawURLEncoding.EncodeToString(dcBytes)

	ucBytes := make([]byte, 4)
	if _, err := rand.Read(ucBytes); err != nil {
		return "", "", err
	}
	userCode = fmt.Sprintf("%04X-%04X", ucBytes[0:2], ucBytes[2:4])

	return deviceCode, userCode, nil
}

// generateDeviceJWT creates a short-lived JWT for the device.
func generateDeviceJWT(dev *DeviceDirectory, issuer string) string {
	now := time.Now()
	header := `{"alg":"HS256","typ":"JWT"}`
	payload := fmt.Sprintf(`{"sub":"%s","iss":"%s","device_id":"%s","org_id":"%s","join_type":"%s","iat":%d,"exp":%d}`,
		dev.DeviceID, issuer, dev.ID, dev.OrgID, dev.JoinType, now.Unix(), now.Add(15*time.Minute).Unix())

	h := base64.RawURLEncoding.EncodeToString([]byte(header))
	p := base64.RawURLEncoding.EncodeToString([]byte(payload))

	// HMAC-SHA256 signature (placeholder — in production use the OIDC signing key)
	sig := sha256.Sum256([]byte(h + "." + p + ".drs-secret"))
	s := base64.RawURLEncoding.EncodeToString(sig[:32])

	return h + "." + p + "." + s
}

// MarshalJSON helper for DeviceDirectory
func (d *DeviceDirectory) MarshalJSON() ([]byte, error) {
	type Alias DeviceDirectory
	return json.Marshal((*Alias)(d))
}

// ValidateDeviceID checks that a device ID is valid.
func ValidateDeviceID(id string) bool {
	if id == "" || len(id) > 255 {
		return false
	}
	// Allow alphanumeric, hyphens, underscores, dots
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// NormalizeDeviceID normalizes a device ID (lowercase, trim).
func NormalizeDeviceID(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}
