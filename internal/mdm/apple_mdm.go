package mdm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// AppleMDM manages Apple device enrollment and MDM commands via APNs push.
type AppleMDM struct {
	apnsCert     tls.Certificate // Apple Push Notification certificate
	apnsTopic    string          // MDM bundle ID (e.g., com.apexaegis.mdm)
	apnsURL      string          // APNs gateway URL
	httpClient   *http.Client
	commandQueue map[string][]MDMCommand // device_token -> pending commands
	mu           sync.RWMutex
	logger       *zap.Logger
}

// MDMCommand represents an MDM command to send to an Apple device.
type MDMCommand struct {
	CommandUUID string
	CommandType string
	Payload     interface{}
}

// NewAppleMDM creates a new Apple MDM engine.
func NewAppleMDM(apnsCertPEM, apnsKeyPEM []byte, apnsTopic string, logger *zap.Logger) (*AppleMDM, error) {
	var apnsCert tls.Certificate
	var err error

	if len(apnsCertPEM) > 0 && len(apnsKeyPEM) > 0 {
		apnsCert, err = tls.X509KeyPair(apnsCertPEM, apnsKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("load APNs certificate: %w", err)
		}
	}

	return &AppleMDM{
		apnsCert:     apnsCert,
		apnsTopic:    apnsTopic,
		apnsURL:      "https://api.push.apple.com/3/device/",
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		commandQueue: make(map[string][]MDMCommand),
		logger:       logger,
	}, nil
}

// MDMCommandXML is the XML structure for an MDM command payload.
type MDMCommandXML struct {
	XMLName    xml.Name `xml:"dict"`
	Command    string   `xml:"key>Command"`
	RequestType string  `xml:"key>RequestType"`
}

// InstallApplicationRequest creates an InstallApplication MDM command.
type InstallApplicationRequest struct {
	CommandUUID  string `xml:"CommandUUID"`
	InstallApplication struct {
		RequestType    string `xml:"RequestType"`
		ITunesStoreID  int    `xml:"iTunesStoreID,omitempty"`
		ManifestURL    string `xml:"ManifestURL,omitempty"`
		Identifier     string `xml:"Identifier"`
	} `xml:"dict"`
}

// BuildInstallApplication creates a command to install an app on the device.
func (a *AppleMDM) BuildInstallApplication(commandUUID, identifier string, itunesID int) *MDMCommand {
	return &MDMCommand{
		CommandUUID: commandUUID,
		CommandType: "InstallApplication",
		Payload: map[string]interface{}{
			"Command":         "InstallApplication",
			"RequestType":     "InstallApplication",
			"iTunesStoreID":   itunesID,
			"Identifier":      identifier,
		},
	}
}

// BuildInstallProfile creates a command to install a .mobileconfig profile.
func (a *AppleMDM) BuildInstallProfile(commandUUID string, profilePayload []byte) *MDMCommand {
	return &MDMCommand{
		CommandUUID: commandUUID,
		CommandType: "InstallProfile",
		Payload: map[string]interface{}{
			"Command":     "InstallProfile",
			"RequestType": "InstallProfile",
			"Payload":     profilePayload,
		},
	}
}

// BuildRemoveProfile creates a command to remove a profile by identifier.
func (a *AppleMDM) BuildRemoveProfile(commandUUID, identifier string) *MDMCommand {
	return &MDMCommand{
		CommandUUID: commandUUID,
		CommandType: "RemoveProfile",
		Payload: map[string]interface{}{
			"Command":     "RemoveProfile",
			"RequestType": "RemoveProfile",
			"Identifier":  identifier,
		},
	}
}

// BuildDeviceInformation creates a command to query device information.
func (a *AppleMDM) BuildDeviceInformation(commandUUID string, queries []string) *MDMCommand {
	return &MDMCommand{
		CommandUUID: commandUUID,
		CommandType: "DeviceInformation",
		Payload: map[string]interface{}{
			"Command":     "DeviceInformation",
			"RequestType": "DeviceInformation",
			"Queries":     queries,
		},
	}
}

// QueueCommand adds a command to the device's pending queue.
func (a *AppleMDM) QueueCommand(deviceToken string, cmd *MDMCommand) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.commandQueue[deviceToken] = append(a.commandQueue[deviceToken], *cmd)
}

// DequeueCommand removes and returns the next command for a device.
func (a *AppleMDM) DequeueCommand(deviceToken string) *MDMCommand {
	a.mu.Lock()
	defer a.mu.Unlock()

	queue := a.commandQueue[deviceToken]
	if len(queue) == 0 {
		return nil
	}

	cmd := queue[0]
	a.commandQueue[deviceToken] = queue[1:]
	return &cmd
}

// PushAPNs sends an APNs push notification to trigger the device to check in.
func (a *AppleMDM) PushAPNs(ctx context.Context, deviceToken string) error {
	if len(a.apnsCert.Certificate) == 0 {
		a.logger.Debug("APNs not configured — skipping push (POC mode)",
			zap.String("device_token", deviceToken),
		)
		return nil
	}

	// APNs HTTP/2 push
	// POST https://api.push.apple.com/3/device/{device_token}
	url := a.apnsURL + deviceToken

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader([]byte("{}")))
	if err != nil {
		return fmt.Errorf("create APNs request: %w", err)
	}

	req.Header.Set("apns-topic", a.apnsTopic)
	req.Header.Set("apns-push-type", "mdm")
	req.Header.Set("apns-priority", "10")
	req.Header.Set("Content-Type", "application/json")

	// Use APNs certificate for mTLS
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{a.apnsCert},
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("APNs push: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("APNs error %d: %s", resp.StatusCode, string(body))
	}

	a.logger.Info("APNs push sent", zap.String("device_token", deviceToken))
	return nil
}

// BuildMobileConfig creates a .mobileconfig payload for SCEP/Wi-Fi/VPN enrollment.
func BuildMobileConfig(scepURL, challenge, caCertPEM, wifiSSID, wifiPassword string) []byte {
	config := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadDisplayName</key>
    <string>Apex Aegis MDM</string>
    <key>PayloadIdentifier</key>
    <string>com.apexaegis.mdm.profile</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>%s</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.security.scep</string>
            <key>PayloadDisplayName</key>
            <string>SCEP Certificate</string>
            <key>PayloadIdentifier</key>
            <string>com.apexaegis.mdm.scep</string>
            <key>PayloadUUID</key>
            <string>%s-scep</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>URL</key>
            <string>%s</string>
            <key>Challenge</key>
            <string>%s</string>
            <key>Subject</key>
            <array>
                <array>
                    <array><string>O</string><string>Apex Aegis</string></array>
                    <array><string>CN</string><string>device</string></array>
                </array>
            </array>
            <key>SubjectAltName</key>
            <string>DNS:device</string>
            <key>KeyType</key>
            <string>RSA</string>
            <key>KeySize</key>
            <integer>2048</integer>
            <key>KeyUsage</key>
            <integer>5</integer>
        </dict>
        %s
    </array>
</dict>
</plist>`,
		generateUUID(),
		generateUUID(),
		scepURL,
		challenge,
		buildWiFiPayload(wifiSSID, wifiPassword),
	)
	return []byte(config)
}

func buildWiFiPayload(ssid, password string) string {
	if ssid == "" {
		return ""
	}
	return fmt.Sprintf(`<dict>
        <key>PayloadType</key>
        <string>com.apple.wifi.managed</string>
        <key>PayloadDisplayName</key>
        <string>WiFi</string>
        <key>PayloadIdentifier</key>
        <string>com.apexaegis.mdm.wifi</string>
        <key>PayloadUUID</key>
        <string>%s-wifi</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
        <key>SSID_STR</key>
        <string>%s</string>
        <key>EncryptionType</key>
        <string>WPA2</string>
        <key>AutoJoin</key>
        <true/>
        <key>DeprecatedPassword</key>
        <string>%s</string>
    </dict>`, generateUUID(), ssid, password)
}

func generateUUID() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		time.Now().UnixNano()%0xFFFFFFFF,
		time.Now().UnixNano()%0xFFFF,
		time.Now().UnixNano()%0xFFFF,
		time.Now().UnixNano()%0xFFFF,
		time.Now().UnixNano()%0xFFFFFFFFFFFF,
	)
}
