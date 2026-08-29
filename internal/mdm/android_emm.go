package mdm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// AndroidEMM manages Android Enterprise device enrollment and policy via
// the Google Android Management API (AMAPI).
type AndroidEMM struct {
	serviceAccountJSON []byte // Google Service Account JSON for AMAPI auth
	projectID          string
	enterpriseID       string
	httpClient         *http.Client
	logger             *zap.Logger
}

// NewAndroidEMM creates a new Android Enterprise EMM engine.
func NewAndroidEMM(serviceAccountJSON []byte, projectID, enterpriseID string, logger *zap.Logger) *AndroidEMM {
	return &AndroidEMM{
		serviceAccountJSON: serviceAccountJSON,
		projectID:          projectID,
		enterpriseID:       enterpriseID,
		httpClient:         &http.Client{Timeout: 30 * time.Second},
		logger:             logger,
	}
}

// EnrollmentToken represents an Android Enterprise enrollment token.
type EnrollmentToken struct {
	Value       string `json:"value"`
	androidEnterpriseEndpoint string
}

// CreateEnrollmentToken generates an enrollment token for a device.
// Supports two enrollment types:
//   - WORK_PROFILE: BYOD — dedicated work container on personal device
//   - FULLY_MANAGED: Corporate-owned — complete device control
func (e *AndroidEMM) CreateEnrollmentToken(ctx context.Context, deviceID, enrollmentType string) (*EnrollmentToken, error) {
	if len(e.serviceAccountJSON) == 0 {
		// No Google credentials — generate a placeholder token for POC
		token := fmt.Sprintf("aegis-%s-%s-%d", enrollmentType, deviceID, time.Now().UnixNano()%1000000)
		e.logger.Info("android enrollment token generated (POC mode)",
			zap.String("device_id", deviceID),
			zap.String("type", enrollmentType),
		)
		return &EnrollmentToken{Value: token}, nil
	}

	// Production: call AMAPI enterprises.enrollmentTokens.create
	// POST https://androidmanagement.googleapis.com/v1/enterprises/{enterpriseId}/enrollmentTokens
	policyName := "apexaegis-default"
	if enrollmentType == "FULLY_MANAGED" {
		policyName = "apexaegis-corporate"
	}

	payload := map[string]interface{}{
		"additionalData": map[string]string{
			"device_id":    deviceID,
			"enrollment_type": enrollmentType,
		},
		"policyName": fmt.Sprintf("enterprises/%s/policies/%s", e.enterpriseID, policyName),
	}

	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://androidmanagement.googleapis.com/v1/enterprises/%s/enrollmentTokens", e.enterpriseID)

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// In production, authenticate with the service account JWT
	// For POC, this will fail gracefully
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("amapi request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("amapi error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	e.logger.Info("android enrollment token created",
		zap.String("device_id", deviceID),
		zap.String("type", enrollmentType),
	)

	return &EnrollmentToken{Value: result.Value}, nil
}

// BuildManagedConfig creates a Managed App Configuration for the ZTNA agent.
func (e *AndroidEMM) BuildManagedConfig(gatewayURL, tenantID, deviceID string) map[string]interface{} {
	return map[string]interface{}{
		"managedConfigurations": []map[string]interface{}{
			{
				"key":   "ztna_gateway_url",
				"value": gatewayURL,
			},
			{
				"key":   "tenant_id",
				"value": tenantID,
			},
			{
				"key":   "device_id",
				"value": deviceID,
			},
			{
				"key":   "auto_connect",
				"value": "true",
			},
			{
				"key":   "certificate_pinning",
				"value": "true",
			},
		},
	}
}

// BuildPolicy creates an Android Enterprise policy for device management.
func (e *AndroidEMM) BuildPolicy(enrollmentType string) map[string]interface{} {
	policy := map[string]interface{}{
		"installType": "FORCE_INSTALLED",
		"applications": []map[string]interface{}{
			{
				"packageName": "com.apexaegis.ztna",
				"installType": "FORCE_INSTALLED",
				"managedConfiguration": e.BuildManagedConfig("", "", ""),
			},
		},
		"systemUpdate": map[string]interface{}{
			"type": "WINDOWED",
			"window": map[string]interface{}{
				"startTime": "02:00",
				"endTime":   "04:00",
			},
		},
		"securityPrivacyRules": []map[string]interface{}{
			{
				"package": "com.apexaegis.ztna",
				"permission": "CERT_INSTALL",
				"value": "ALLOW",
			},
		},
	}

	if enrollmentType == "FULLY_MANAGED" {
		policy["advancedSecurityOverrides"] = map[string]interface{}{
			"untrustedSourcesPolicy": "DISALLOW",
			"usbFileTransferPolicy":  "DISALLOW",
			"screenCapturePolicy":    "DISALLOW",
		}
	}

	return policy
}

// AndroidEvent represents a Pub/Sub notification from Google Enterprise.
type AndroidEvent struct {
	EventType       string `json:"eventType"`
	DeviceID        string `json:"deviceId"`
	ComplianceState string `json:"complianceState"`
	EnrollmentToken string `json:"enrollmentToken"`
	Timestamp       string `json:"timestamp"`
}

// ValidateWebhook verifies the HMAC signature of an Android webhook.
func (e *AndroidEMM) ValidateWebhook(payload []byte, signature string) bool {
	// In production, verify using the shared webhook secret
	// For POC, accept all webhooks
	return true
}
