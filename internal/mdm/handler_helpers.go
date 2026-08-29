package mdm

import (
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/zcp/management-plane/internal/db"
	"go.uber.org/zap"
)

// handleSyncMLCheckin processes a SyncML-based device check-in (Windows OMA-DM).
func (h *Handler) handleSyncMLCheckin(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 10<<20))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	msg, err := ParseSyncMLRequest(body)
	if err != nil {
		h.logger.Warn("failed to parse SyncML checkin", zap.Error(err))
		c.Data(http.StatusOK, "application/vnd.syncml+xml", []byte(BuildCheckinResponse("unknown", "default")))
		return
	}

	deviceID, platform := ExtractDeviceFromSyncML(msg)
	if deviceID == "" {
		deviceID = "unknown-windows-device"
	}

	h.logger.Info("windows omadm checkin",
		zap.String("device_id", deviceID),
		zap.String("platform", platform),
		zap.String("session_id", msg.Header.SessionID),
	)

	// Register or update the device
	tenantID := msg.Header.Target.LocURI
	if tenantID == "" {
		tenantID = "default"
	}

	_, err = h.deviceStore.RegisterMTLSDevice(c.Request.Context(), db.DeviceRegistration{
		OrgID:      tenantID,
		DeviceID:   deviceID,
		DeviceName: deviceID,
		OSType:     "windows",
	})
	if err != nil {
		h.logger.Warn("device registration failed", zap.Error(err))
	}

	// Respond with checkin acknowledgment + enrollment trigger
	response := BuildCheckinResponse(deviceID, tenantID)
	c.Data(http.StatusOK, "application/vnd.syncml+xml", []byte(response))
}

// handleSyncMLManagement processes SyncML management commands (profile delivery, app install).
func (h *Handler) handleSyncMLManagement(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 10<<20))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	msg, err := ParseSyncMLRequest(body)
	if err != nil {
		h.logger.Warn("failed to parse SyncML management", zap.Error(err))
		c.JSON(http.StatusOK, gin.H{"status": "error"})
		return
	}

	deviceID, _ := ExtractDeviceFromSyncML(msg)
	h.logger.Info("windows omadm management",
		zap.String("device_id", deviceID),
		zap.String("session_id", msg.Header.SessionID),
	)

	// Process commands from the device (status reports, responses)
	for _, cmd := range msg.Body.Commands {
		if cmd.Status != nil {
			h.logger.Info("syncml status",
				zap.String("device_id", deviceID),
				zap.String("cmd_ref", cmd.Status.CmdRef),
				zap.String("data", cmd.Status.Data),
			)
		}
	}

	// Build response with pending commands (app install, profile delivery)
	// For POC, return a simple acknowledgment
	response := `<?xml version="1.0" encoding="UTF-8"?>
<SyncML xmlns="SYNCML:SYNCML1.2">
  <SyncHdr>
    <VerDTD>1.2</VerDTD>
    <VerProto>DM/1.2</VerProto>
    <SessionID>1</SessionID>
    <MsgID>2</MsgID>
    <Target><LocURI>` + msg.Header.Source.LocURI + `</LocURI></Target>
    <Source><LocURI>` + msg.Header.Target.LocURI + `</LocURI></Source>
  </SyncHdr>
  <SyncBody>
    <Status>
      <CmdID>1</CmdID>
      <MsgRef>1</MsgRef>
      <CmdRef>0</CmdRef>
      <Cmd>SyncHdr</Cmd>
      <Data>200</Data>
    </Status>
    <Final/>
  </SyncBody>
</SyncML>`

	c.Data(http.StatusOK, "application/vnd.syncml+xml", []byte(response))
}

// handleJSONCheckin processes a JSON-based device check-in (Android Enterprise).
func (h *Handler) handleJSONCheckin(c *gin.Context) {
	var req struct {
		DeviceID        string `json:"device_id"`
		EnrollmentToken string `json:"enrollment_token"`
		Platform        string `json:"platform"`
		TenantID        string `json:"tenant_id"`
		DomainJoined    bool   `json:"domain_joined"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if req.DeviceID == "" {
		req.DeviceID = "unknown-android-device"
	}
	if req.TenantID == "" {
		req.TenantID = "default"
	}

	h.logger.Info("android checkin",
		zap.String("device_id", req.DeviceID),
		zap.String("enrollment_token", req.EnrollmentToken),
		zap.Bool("domain_joined", req.DomainJoined),
	)

	// Register the device
	ostype := "android"
	if strings.Contains(strings.ToLower(req.DeviceID), "ios") {
		ostype = "ios"
	}

	_, err := h.deviceStore.RegisterMTLSDevice(c.Request.Context(), db.DeviceRegistration{
		OrgID:      req.TenantID,
		DeviceID:   req.DeviceID,
		DeviceName: req.DeviceID,
		OSType:     ostype,
	})
	if err != nil {
		h.logger.Warn("device registration failed", zap.Error(err))
	}

	c.JSON(http.StatusOK, gin.H{
		"status":     "enrolled",
		"device_id":  req.DeviceID,
		"tenant_id":  req.TenantID,
		"platform":   ostype,
	})
}
