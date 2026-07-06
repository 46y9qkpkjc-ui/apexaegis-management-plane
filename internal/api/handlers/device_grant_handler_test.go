package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
	"github.com/zcp/management-plane/internal/grant"
)

type fakeDevices struct {
	detail *db.DeviceDetail
	err    error
}

func (f fakeDevices) GetDeviceDetail(_ context.Context, _, _ string) (*db.DeviceDetail, error) {
	return f.detail, f.err
}

func newTestGrantHandler(t *testing.T, devices deviceComplianceSource, segmentsJSON string) *DeviceGrantHandler {
	t.Helper()
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	iss, err := grant.NewIssuer(key)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	segs, err := NewConfigDCSegments(segmentsJSON)
	if err != nil {
		t.Fatalf("NewConfigDCSegments: %v", err)
	}
	return NewDeviceGrantHandler(devices, iss, segs, zap.NewNop())
}

func doGrantRequest(h *DeviceGrantHandler, orgID, deviceID string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/client/dc-grant", nil)
	if orgID != "" {
		c.Set("org_id", orgID)
	}
	if deviceID != "" {
		c.Set("device_id", deviceID)
		// DeviceMTLSAuth sets device_cn (the cert CN) alongside device_id; the grant's
		// did is signed from the CN. In these tests deviceID stands in for the CN.
		c.Set("device_cn", deviceID)
	}
	h.IssueDCGrant(c)
	return w
}

func compliantDetail() *db.DeviceDetail {
	return &db.DeviceDetail{Posture: &db.DevicePostureReport{Compliant: true}}
}

func decodeGrant(t *testing.T, token string) grant.Claims {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var c grant.Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return c
}

func TestIssueDCGrant_Compliant(t *testing.T) {
	h := newTestGrantHandler(t, fakeDevices{detail: compliantDetail()}, `{"*":{"host":"10.10.1.4"}}`)
	w := doGrantRequest(h, "org1", "PC01$")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
	}
	var resp struct {
		Grant   string `json:"grant"`
		DCHost  string `json:"dc_host"`
		DCPorts []int  `json:"dc_ports"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Grant == "" || resp.DCHost != "10.10.1.4" || len(resp.DCPorts) == 0 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	// The minted grant must be a device DC-scope grant bound to this device.
	claims := decodeGrant(t, resp.Grant)
	if claims.Type != grant.TypeDevice || claims.Subject != "" ||
		claims.DeviceID != "PC01$" || claims.TargetHost != "10.10.1.4" || len(claims.TargetPorts) == 0 {
		t.Fatalf("unexpected grant claims: %+v", claims)
	}
}

// The machine tunnel is device-scoped + pre-logon, so posture must NOT gate it —
// a non-compliant OR missing posture report still gets a dc-grant (posture is
// enforced on the user/SWG tunnel post-login). Gating here would be a chicken-and-
// egg: posture needs the tunnel, the tunnel needs the grant.
func TestIssueDCGrant_PostureDoesNotGateMachineTunnel(t *testing.T) {
	cases := map[string]*db.DeviceDetail{
		"non-compliant posture": {Posture: &db.DevicePostureReport{Compliant: false}},
		"no posture report":     {},
	}
	for name, detail := range cases {
		t.Run(name, func(t *testing.T) {
			h := newTestGrantHandler(t, fakeDevices{detail: detail}, `{"*":{"host":"10.10.1.4"}}`)
			w := doGrantRequest(h, "org1", "PC01$")
			if w.Code != http.StatusOK {
				t.Fatalf("expected 200 (posture must not gate the machine tunnel), got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

// A suspended/revoked device IS denied — the machine tunnel gates on device status.
func TestIssueDCGrant_SuspendedDeviceDenied(t *testing.T) {
	h := newTestGrantHandler(t, fakeDevices{detail: &db.DeviceDetail{Device: db.DeviceInventoryItem{Status: "suspended"}}}, `{"*":{"host":"10.10.1.4"}}`)
	w := doGrantRequest(h, "org1", "PC01$")
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a suspended device, got %d", w.Code)
	}
}

func TestIssueDCGrant_NoSegment(t *testing.T) {
	h := newTestGrantHandler(t, fakeDevices{detail: compliantDetail()}, ``)
	w := doGrantRequest(h, "org1", "PC01$")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when no DC segment, got %d", w.Code)
	}
}

func TestIssueDCGrant_NoIdentity(t *testing.T) {
	h := newTestGrantHandler(t, fakeDevices{detail: compliantDetail()}, `{"*":{"host":"10.10.1.4"}}`)
	w := doGrantRequest(h, "", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without device identity, got %d", w.Code)
	}
}

func TestConfigDCSegments_PerTenantAndDefault(t *testing.T) {
	segs, err := NewConfigDCSegments(`{"orgA":{"host":"10.10.1.4","ports":[88,445]},"*":{"host":"10.20.1.4"}}`)
	if err != nil {
		t.Fatalf("NewConfigDCSegments: %v", err)
	}
	a, ok := segs.Resolve("orgA")
	if !ok || a.Host != "10.10.1.4" || len(a.Ports) != 2 {
		t.Fatalf("orgA resolve: %+v ok=%v", a, ok)
	}
	d, ok := segs.Resolve("orgZ") // falls back to "*", default ports
	if !ok || d.Host != "10.20.1.4" || len(d.Ports) != len(DefaultDCPorts()) {
		t.Fatalf("default resolve: %+v ok=%v", d, ok)
	}
}
