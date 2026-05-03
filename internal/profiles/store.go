package profiles

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ProfileType enumerates the supported security profile categories.
type ProfileType string

const (
	TypeATP           ProfileType = "atp"
	TypeSSL           ProfileType = "ssl"
	TypeDNS           ProfileType = "dns"
	TypeWeb           ProfileType = "web"
	TypeDevicePosture ProfileType = "device-posture"
)

// Profile is a generic wrapper: common metadata + type-specific config stored as raw JSON.
type Profile struct {
	ID        string          `json:"id"`
	Type      ProfileType     `json:"type"`
	Name      string          `json:"name"`
	Enabled   bool            `json:"enabled"`
	Builtin   bool            `json:"builtin"`
	Sequence  int             `json:"sequence"`
	Config    json.RawMessage `json:"config"`
	CreatedBy string          `json:"created_by"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedBy string          `json:"updated_by"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// Store is an in-memory security profile store.
type Store struct {
	mu       sync.RWMutex
	profiles map[string]*Profile // keyed by Profile.ID
}

// NewStore creates a profile store seeded with defaults.
func NewStore() *Store {
	s := &Store{profiles: make(map[string]*Profile)}
	s.seedDefaults()
	return s
}

// ── CRUD ─────────────────────────────────────────────────────────

// List returns all profiles of the given type, sorted by Sequence.
func (s *Store) List(pt ProfileType) []*Profile {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*Profile, 0)
	for _, p := range s.profiles {
		if p.Type == pt {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Sequence < out[j].Sequence
	})
	return out
}

// Get returns a single profile by ID.
func (s *Store) Get(id string) (*Profile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.profiles[id]
	return p, ok
}

// Create adds a new profile. Sequence is auto-assigned as max+10.
func (s *Store) Create(p *Profile, actor string) (*Profile, error) {
	if p.Name == "" {
		return nil, fmt.Errorf("profile name is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if p.ID == "" {
		p.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	if _, exists := s.profiles[p.ID]; exists {
		return nil, fmt.Errorf("profile %q already exists", p.ID)
	}

	// Auto-assign sequence
	maxSeq := 0
	for _, existing := range s.profiles {
		if existing.Type == p.Type && existing.Sequence > maxSeq {
			maxSeq = existing.Sequence
		}
	}
	p.Sequence = maxSeq + 10

	now := time.Now()
	p.CreatedBy = actor
	p.CreatedAt = now
	p.UpdatedBy = actor
	p.UpdatedAt = now

	s.profiles[p.ID] = p
	return p, nil
}

// Update replaces a profile's mutable fields. Builtin profiles cannot be renamed.
func (s *Store) Update(id string, patch *Profile, actor string) (*Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.profiles[id]
	if !ok {
		return nil, fmt.Errorf("profile %q not found", id)
	}

	if existing.Builtin && patch.Name != existing.Name {
		return nil, fmt.Errorf("cannot rename built-in profile %q", existing.Name)
	}

	existing.Name = patch.Name
	existing.Enabled = patch.Enabled
	if patch.Config != nil {
		existing.Config = patch.Config
	}
	if patch.Sequence > 0 {
		existing.Sequence = patch.Sequence
	}

	existing.UpdatedBy = actor
	existing.UpdatedAt = time.Now()
	return existing, nil
}

// Delete removes a profile by ID. Builtin profiles cannot be deleted.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.profiles[id]
	if !ok {
		return fmt.Errorf("profile %q not found", id)
	}
	if p.Builtin {
		return fmt.Errorf("cannot delete built-in profile %q", p.Name)
	}
	delete(s.profiles, id)
	return nil
}

// Toggle flips the enabled state of a profile.
func (s *Store) Toggle(id string, enabled bool, actor string) (*Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.profiles[id]
	if !ok {
		return nil, fmt.Errorf("profile %q not found", id)
	}
	p.Enabled = enabled
	p.UpdatedBy = actor
	p.UpdatedAt = time.Now()
	return p, nil
}

// ── Default seeds ────────────────────────────────────────────────

func (s *Store) seedDefaults() {
	now := time.Now()
	defaults := []Profile{
		// ── ATP ──
		{ID: "atp-1", Type: TypeATP, Name: "Default-ATP", Enabled: true, Builtin: true, Sequence: 10,
			Config: raw(`{"antivirusAction":"block","sandboxAction":"alert","ipsAction":"block","fileTypeBlocking":["exe","dll","bat"],"scanProtocols":["HTTP","HTTPS","FTP","SMTP"],"sandboxFileTypes":["exe","dll","pdf","docx"]}`)},
		{ID: "atp-2", Type: TypeATP, Name: "Strict-ATP", Enabled: true, Builtin: true, Sequence: 20,
			Config: raw(`{"antivirusAction":"block","sandboxAction":"block","ipsAction":"block","fileTypeBlocking":["exe","dll","bat","ps1","vbs","js"],"scanProtocols":["HTTP","HTTPS","FTP","SMTP","IMAP","POP3"],"sandboxFileTypes":["exe","dll","pdf","docx","xlsx","zip"]}`)},
		{ID: "atp-3", Type: TypeATP, Name: "Monitor-Only", Enabled: true, Builtin: false, Sequence: 30,
			Config: raw(`{"antivirusAction":"alert","sandboxAction":"alert","ipsAction":"alert","fileTypeBlocking":[],"scanProtocols":["HTTP","HTTPS"],"sandboxFileTypes":["exe"]}`)},

		// ── SSL ──
		{ID: "ssl-1", Type: TypeSSL, Name: "Full Inspection", Enabled: true, Builtin: true, Sequence: 10,
			Config: raw(`{"mode":"full-inspection","exemptCategories":["Financial Services","Health"],"exemptDomains":[],"caBundle":"ApexAegis-SSL-CA","logDecryptedTraffic":true,"untrustedCertAction":"block","expiredCertAction":"allow-warn"}`)},
		{ID: "ssl-2", Type: TypeSSL, Name: "Certificate Inspection", Enabled: true, Builtin: true, Sequence: 20,
			Config: raw(`{"mode":"certificate-inspection","exemptCategories":[],"exemptDomains":["*.microsoft.com","*.apple.com"],"caBundle":"ApexAegis-SSL-CA","logDecryptedTraffic":false,"untrustedCertAction":"allow-warn","expiredCertAction":"block"}`)},
		{ID: "ssl-3", Type: TypeSSL, Name: "No Inspection", Enabled: false, Builtin: true, Sequence: 30,
			Config: raw(`{"mode":"no-inspection","exemptCategories":[],"exemptDomains":[],"caBundle":"","logDecryptedTraffic":false,"untrustedCertAction":"allow","expiredCertAction":"allow"}`)},

		// ── DNS ──
		{ID: "dns-1", Type: TypeDNS, Name: "Block-Malicious", Enabled: true, Builtin: true, Sequence: 10,
			Config: raw(`{"mode":"blocklist","blockCategories":["malware","phishing","botnet","cryptomining"],"customBlockDomains":[],"customAllowDomains":[],"safesearch":false,"logQueries":true}`)},
		{ID: "dns-2", Type: TypeDNS, Name: "Block-NRD-NOD", Enabled: true, Builtin: true, Sequence: 20,
			Config: raw(`{"mode":"blocklist","blockCategories":["newly-registered","newly-observed","dga"],"customBlockDomains":[],"customAllowDomains":[],"safesearch":false,"logQueries":true}`)},
		{ID: "dns-3", Type: TypeDNS, Name: "Family-Safe", Enabled: true, Builtin: true, Sequence: 30,
			Config: raw(`{"mode":"blocklist","blockCategories":["adult","gambling","violence","drugs"],"customBlockDomains":[],"customAllowDomains":[],"safesearch":true,"logQueries":false}`)},
		{ID: "dns-4", Type: TypeDNS, Name: "Custom-Block", Enabled: true, Builtin: false, Sequence: 40,
			Config: raw(`{"mode":"blocklist","blockCategories":["malware","phishing"],"customBlockDomains":["evil.example.com","bad-domain.test"],"customAllowDomains":[],"safesearch":false,"logQueries":true}`)},

		// ── Web ──
		{ID: "web-1", Type: TypeWeb, Name: "Default-Web-Filter", Enabled: true, Builtin: true, Sequence: 10,
			Config: raw(`{"action":"block","categories":["malware","phishing","adult","gambling"],"blockPages":true,"blockFileTypes":["exe","bat","cmd"],"customBlockUrls":[],"customAllowUrls":[],"logAccess":true}`)},
		{ID: "web-2", Type: TypeWeb, Name: "Strict-Web-Filter", Enabled: true, Builtin: true, Sequence: 20,
			Config: raw(`{"action":"block","categories":["malware","phishing","adult","gambling","social-media","streaming","gaming","p2p","proxy-anonymizer"],"blockPages":true,"blockFileTypes":["exe","bat","cmd","ps1","vbs","msi"],"customBlockUrls":[],"customAllowUrls":[],"logAccess":true}`)},
		{ID: "web-3", Type: TypeWeb, Name: "Monitor-Only", Enabled: true, Builtin: true, Sequence: 30,
			Config: raw(`{"action":"monitor","categories":["malware","phishing"],"blockPages":false,"blockFileTypes":[],"customBlockUrls":[],"customAllowUrls":[],"logAccess":true}`)},
		{ID: "web-4", Type: TypeWeb, Name: "Custom-Web-Policy", Enabled: true, Builtin: false, Sequence: 40,
			Config: raw(`{"action":"warn","categories":["social-media","streaming"],"blockPages":true,"blockFileTypes":["exe"],"customBlockUrls":["https://risky-site.example.com"],"customAllowUrls":["https://approved-tool.example.com"],"logAccess":true}`)},

		// ── Device Posture ──
		{ID: "dp-1", Type: TypeDevicePosture, Name: "Corporate Managed", Enabled: true, Builtin: true, Sequence: 10,
			Config: raw(`{"platforms":["windows","macos"],"matchType":"all","checks":[{"id":"chk-1","type":"disk-encryption","enabled":true,"action":"block"},{"id":"chk-2","type":"firewall","enabled":true,"action":"block"},{"id":"chk-3","type":"antivirus","enabled":true,"action":"block"},{"id":"chk-4","type":"os-version","enabled":true,"operator":"gte","value":"10.0","action":"warn"},{"id":"chk-5","type":"screen-lock","enabled":true,"action":"warn"},{"id":"chk-6","type":"domain-joined","enabled":true,"action":"block"}]}`)},
		{ID: "dp-2", Type: TypeDevicePosture, Name: "BYOD Baseline", Enabled: true, Builtin: true, Sequence: 20,
			Config: raw(`{"platforms":["windows","macos","linux","ios","android"],"matchType":"all","checks":[{"id":"chk-1","type":"screen-lock","enabled":true,"action":"block"},{"id":"chk-2","type":"jailbreak","enabled":true,"action":"block"},{"id":"chk-3","type":"os-version","enabled":true,"operator":"gte","value":"12.0","action":"warn"},{"id":"chk-4","type":"disk-encryption","enabled":true,"action":"warn"}]}`)},
		{ID: "dp-3", Type: TypeDevicePosture, Name: "High-Security Zone", Enabled: true, Builtin: false, Sequence: 30,
			Config: raw(`{"platforms":["windows","macos","linux"],"matchType":"all","checks":[{"id":"chk-1","type":"disk-encryption","enabled":true,"action":"block"},{"id":"chk-2","type":"firewall","enabled":true,"action":"block"},{"id":"chk-3","type":"antivirus","enabled":true,"action":"block"},{"id":"chk-4","type":"certificate","enabled":true,"action":"block"},{"id":"chk-5","type":"domain-joined","enabled":true,"action":"block"},{"id":"chk-6","type":"mfa-enrolled","enabled":true,"action":"block"},{"id":"chk-7","type":"patch-level","enabled":true,"operator":"lte","value":"30","action":"block"},{"id":"chk-8","type":"screen-lock","enabled":true,"action":"block"}]}`)},
		{ID: "dp-4", Type: TypeDevicePosture, Name: "Linux Workstations", Enabled: false, Builtin: false, Sequence: 40,
			Config: raw(`{"platforms":["linux"],"matchType":"any","checks":[{"id":"chk-1","type":"disk-encryption","enabled":true,"action":"warn"},{"id":"chk-2","type":"firewall","enabled":true,"action":"warn"}]}`)},
	}

	for i := range defaults {
		d := &defaults[i]
		d.CreatedBy = "system"
		d.CreatedAt = now
		d.UpdatedBy = "system"
		d.UpdatedAt = now
		s.profiles[d.ID] = d
	}
}

func raw(s string) json.RawMessage { return json.RawMessage(s) }
