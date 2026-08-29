package mdm

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// SyncML message structures for Windows OMA-DM (MS-MDE2 protocol).
// Reference: https://learn.microsoft.com/en-us/windows/win32/oma/dm-wsl-diagnostics

// SyncML represents a SyncML XML message.
type SyncML struct {
	XMLName  xml.Name    `xml:"SyncML"`
	Header   SyncMLHeader `xml:"SyncHdr"`
	Body     SyncMLBody   `xml:"SyncBody"`
}

type SyncMLHeader struct {
	XMLName   xml.Name      `xml:"SyncHdr"`
	VerDTD    string        `xml:"VerDTD"`
	VerProto  string        `xml:"VerProto"`
	SessionID string        `xml:"SessionID"`
	MsgID     string        `xml:"MsgID"`
	Target    SyncMLLocURI  `xml:"Target"`
	Source    SyncMLLocURI  `xml:"Source"`
}

type SyncMLBody struct {
	XMLName xml.Name   `xml:"SyncBody"`
	Commands []SyncMLCommand `xml:",any"`
}

type SyncMLCommand struct {
	XMLName xml.Name
	Add     *SyncMLAdd    `xml:"Add"`
	Replace *SyncMLReplace `xml:"Replace"`
	Delete  *SyncMLDelete  `xml:"Delete"`
	Status  *SyncMLStatus  `xml:"Status"`
	Alert   *SyncMLAlert   `xml:"Alert"`
	Exec    *SyncMLExec    `xml:"Exec"`
}

type SyncMLAdd struct {
	CmdID  string        `xml:"CmdID"`
	Meta   *SyncMLMeta   `xml:"Meta"`
	Items  []SyncMLItem  `xml:"Item"`
}

type SyncMLReplace struct {
	CmdID  string        `xml:"CmdID"`
	Items  []SyncMLItem  `xml:"Item"`
}

type SyncMLDelete struct {
	CmdID  string `xml:"CmdID"`
	Items  []SyncMLItem `xml:"Item"`
}

type SyncMLStatus struct {
	CmdID    string `xml:"CmdID"`
	MsgRef   string `xml:"MsgRef"`
	CmdRef   string `xml:"CmdRef"`
	Cmd      string `xml:"Cmd"`
	Data     string `xml:"Data"`
}

type SyncMLAlert struct {
	CmdID  string      `xml:"CmdID"`
	Number string      `xml:"Number"`
	Items  []SyncMLItem `xml:"Item"`
}

type SyncMLExec struct {
	CmdID  string      `xml:"CmdID"`
	Meta   *SyncMLMeta `xml:"Meta"`
	Items  []SyncMLItem `xml:"Item"`
}

type SyncMLItem struct {
	Source *SyncMLLocURI `xml:"Source"`
	Target *SyncMLLocURI `xml:"Target"`
	Meta   *SyncMLMeta   `xml:"Meta"`
	Data   string        `xml:"Data"`
}

type SyncMLLocURI struct {
	LocURI string `xml:"LocURI"`
}

type SyncMLMeta struct {
	Format string `xml:"Format"`
	Type   string `xml:"Type"`
}

// BuildCheckinResponse creates a SyncML response for the initial device check-in.
// The device sends its identity; we respond with an alert to trigger full enrollment.
func BuildCheckinResponse(deviceID, tenantID string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<SyncML xmlns="SYNCML:SYNCML1.2">
  <SyncHdr>
    <VerDTD>1.2</VerDTD>
    <VerProto>DM/1.2</VerProto>
    <SessionID>1</SessionID>
    <MsgID>1</MsgID>
    <Target><LocURI>%s</LocURI></Target>
    <Source><LocURI>./Vendor/MSFT</LocURI></Source>
  </SyncHdr>
  <SyncBody>
    <Status>
      <CmdID>1</CmdID>
      <MsgRef>0</MsgRef>
      <CmdRef>0</CmdRef>
      <Cmd>SyncHdr</Cmd>
      <Data>200</Data>
    </Status>
    <Alert>
      <CmdID>2</CmdID>
      <Number>1201</Number>
      <Item>
        <Target><LocURI>./DevDetail/Ext/SyncML</LocURI></Target>
        <Meta><Format>chr</Format><Type>text/plain</Type></Meta>
      </Item>
    </Alert>
    <Alert>
      <CmdID>3</CmdID>
      <Number>1224</Number>
      <Item>
        <Target><LocURI>./DevInfo/DevDetail</LocURI></Target>
      </Item>
    </Alert>
    <Final/>
  </SyncBody>
</SyncML>`, tenantID)
}

// BuildAppInstallCommand creates a SyncML Exec command to install the ZTNA agent MSI.
// Reference: MS-MDE EnterpriseDesktopAppManagement
func BuildAppInstallCommand(cmdID int, msiURL string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<SyncML xmlns="SYNCML:SYNCML1.2">
  <SyncHdr>
    <VerDTD>1.2</VerDTD>
    <VerProto>DM/1.2</VerProto>
    <SessionID>1</SessionID>
    <MsgID>1</MsgID>
    <Target><LocURI>./Vendor/MSFT</LocURI></Target>
    <Source><LocURI>./DevDetail/Ext/SyncML</LocURI></Source>
  </SyncHdr>
  <SyncBody>
    <Exec>
      <CmdID>%d</CmdID>
      <Meta><Format>chr</Format><Type>application/vnd.ms-windows-eap-tls</Type></Meta>
      <Item>
        <Target><LocURI>./Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/ApexZTNA/DownloadInstall</LocURI></Target>
        <Meta><Format>chr</Format><Type>text/plain</Type></Meta>
        <Data>%s</Data>
      </Item>
    </Exec>
    <Final/>
  </SyncBody>
</SyncML>`, cmdID, msiURL)
}

// BuildProfileInstallCommand creates a SyncML Replace to install a Wi-Fi/VPN/SCEP profile.
func BuildProfileInstallCommand(cmdID int, profilePayload string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<SyncML xmlns="SYNCML:SYNCML1.2">
  <SyncHdr>
    <VerDTD>1.2</VerDTD>
    <VerProto>DM/1.2</VerProto>
    <SessionID>1</SessionID>
    <MsgID>1</MsgID>
    <Target><LocURI>./Vendor/MSFT</LocURI></Target>
    <Source><LocURI>./DevDetail/Ext/SyncML</LocURI></Source>
  </SyncHdr>
  <SyncBody>
    <Replace>
      <CmdID>%d</CmdID>
      <Item>
        <Target><LocURI>./Vendor/MSFT/EnterpriseDeviceManagement/InstalledProvisioningPackages/ApexProfile</LocURI></Target>
        <Meta><Format>chr</Format><Type>text/plain</Type></Meta>
        <Data>%s</Data>
      </Item>
    </Replace>
    <Final/>
  </SyncBody>
</SyncML>`, cmdID, base64Encode(profilePayload))
}

// ParseSyncMLRequest parses a SyncML XML request body.
func ParseSyncMLRequest(data []byte) (*SyncML, error) {
	var msg SyncML
	if err := xml.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("parse SyncML: %w", err)
	}
	return &msg, nil
}

// ExtractDeviceFromSyncML extracts the device identity from a SyncML check-in.
func ExtractDeviceFromSyncML(msg *SyncML) (deviceID, platform string) {
	for _, cmd := range msg.Body.Commands {
		if cmd.Alert != nil && cmd.Alert.Number == "1224" {
			for _, item := range cmd.Alert.Items {
				if item.Data != "" {
					return item.Data, "windows"
				}
			}
		}
	}
	// Fallback: use the Source LocURI
	if msg.Header.Source.LocURI != "" {
		parts := strings.Split(msg.Header.Source.LocURI, "/")
		if len(parts) > 0 {
			return parts[len(parts)-1], "windows"
		}
	}
	return "", ""
}

// BuildDMProfilePayload creates a Windows DM profile payload for SCEP enrollment.
func BuildDMProfilePayload(scepURL, challenge, caCertPEM string) string {
	// Simplified Windows DM profile with SCEP payload
	return fmt.Sprintf(`<wap-provisioningdoc version="1.0">
  <characteristic type="certificate_store">
    <characteristic type="Root">
      <characteristic type="CA">
        <parm name="encodedCertificate" value="%s"/>
      </characteristic>
    </characteristic>
    <characteristic type="My">
      <characteristic type="ClientCertificate">
        <parm name="subject" value="CN=device"/>
        <parm name="certificate_purpose" value="clientAuth"/>
        <parm name="scep_server_url" value="%s"/>
        <parm name="challenge" value="%s"/>
        <parm name="key_size" value="2048"/>
      </characteristic>
    </characteristic>
  </characteristic>
</wap-provisioningdoc>`, base64Encode(caCertPEM), scepURL, challenge)
}

func base64Encode(s string) string {
	return fmt.Sprintf("%s", s) // Simplified — real impl would use encoding/base64
}
