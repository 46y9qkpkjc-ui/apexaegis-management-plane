package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// WhoisResult is the whois_lookup return contract.
type WhoisResult struct {
	RegistrableDomain string   `json:"registrable_domain"`
	Registrar         string   `json:"registrar"`
	Created           string   `json:"created"`
	Expires           string   `json:"expires"`
	AgeDays           int      `json:"age_days"`
	RegistrantOrg     string   `json:"registrant_org"`
	RegistrantCountry string   `json:"registrant_country"`
	PrivacyProtected  bool     `json:"privacy_protected"`
	Nameservers       []string `json:"nameservers"`
	Error             string   `json:"error,omitempty"`
}

type rdapEntity struct {
	Roles      []string          `json:"roles"`
	VcardArray []json.RawMessage `json:"vcardArray"`
}

type rdapResponse struct {
	LDHName string `json:"ldhName"`
	Events  []struct {
		EventAction string `json:"eventAction"`
		EventDate   string `json:"eventDate"`
	} `json:"events"`
	Entities    []rdapEntity `json:"entities"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
}

// ParseRDAP maps an RDAP domain response to the whois contract. `now` is passed
// for deterministic age computation (testability).
func ParseRDAP(body []byte, now time.Time) (WhoisResult, error) {
	var r rdapResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return WhoisResult{}, err
	}
	res := WhoisResult{RegistrableDomain: strings.ToLower(r.LDHName)}
	for _, e := range r.Events {
		switch e.EventAction {
		case "registration":
			res.Created = e.EventDate
			if t, err := time.Parse(time.RFC3339, e.EventDate); err == nil {
				res.AgeDays = int(now.Sub(t).Hours() / 24)
			}
		case "expiration":
			res.Expires = e.EventDate
		}
	}
	for _, ns := range r.Nameservers {
		if ns.LDHName != "" {
			res.Nameservers = append(res.Nameservers, strings.ToLower(ns.LDHName))
		}
	}
	for _, ent := range r.Entities {
		if hasRole(ent.Roles, "registrar") && res.Registrar == "" {
			res.Registrar = vcardField(ent.VcardArray, "fn")
		}
		if hasRole(ent.Roles, "registrant") {
			res.RegistrantOrg = vcardField(ent.VcardArray, "org")
			res.RegistrantCountry = vcardCountry(ent.VcardArray)
			if res.RegistrantOrg == "" {
				res.PrivacyProtected = true // registrant redacted / privacy service
			}
		}
	}
	return res, nil
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if strings.EqualFold(r, want) {
			return true
		}
	}
	return false
}

// vcardField pulls a jCard field value: vcardArray = ["vcard", [[name,params,type,value],…]].
func vcardField(vcard []json.RawMessage, field string) string {
	if len(vcard) < 2 {
		return ""
	}
	var entries [][]json.RawMessage
	if err := json.Unmarshal(vcard[1], &entries); err != nil {
		return ""
	}
	for _, e := range entries {
		if len(e) < 4 {
			continue
		}
		var name string
		if json.Unmarshal(e[0], &name) == nil && strings.EqualFold(name, field) {
			var val string
			if json.Unmarshal(e[3], &val) == nil {
				return val
			}
		}
	}
	return ""
}

// vcardCountry extracts the country from the jCard "adr" structured value (last element).
func vcardCountry(vcard []json.RawMessage) string {
	if len(vcard) < 2 {
		return ""
	}
	var entries [][]json.RawMessage
	if err := json.Unmarshal(vcard[1], &entries); err != nil {
		return ""
	}
	for _, e := range entries {
		if len(e) < 4 {
			continue
		}
		var name string
		if json.Unmarshal(e[0], &name) == nil && strings.EqualFold(name, "adr") {
			var parts []string
			if json.Unmarshal(e[3], &parts) == nil && len(parts) > 0 {
				return parts[len(parts)-1] // country is the last ADR component
			}
		}
	}
	return ""
}

// whoisTool queries RDAP (via the rdap.org bootstrap redirector). No API key.
type whoisTool struct {
	http *http.Client
	now  func() time.Time
}

func NewWhoisTool() Tool {
	return whoisTool{http: &http.Client{Timeout: 8 * time.Second}, now: time.Now}
}

func (whoisTool) Name() string { return "whois_lookup" }

func (whoisTool) Definition() ToolDef {
	return ToolDef{
		Name: "whois_lookup",
		Description: "Registration facts from WHOIS/RDAP for the registrable domain (eTLD+1). " +
			"Returns registrar, created/expires dates, computed age_days, registrant org/country " +
			"(or redacted under privacy), and nameservers. Call when domain age or ownership could " +
			"change the verdict.",
		InputSchema: domainInputSchema,
	}
}

func (w whoisTool) Run(ctx context.Context, _, etld1 string) (json.RawMessage, error) {
	url := "https://rdap.org/domain/" + etld1
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return json.Marshal(WhoisResult{RegistrableDomain: etld1, Error: err.Error()})
	}
	req.Header.Set("Accept", "application/rdap+json")
	resp, err := w.http.Do(req)
	if err != nil {
		return json.Marshal(WhoisResult{RegistrableDomain: etld1, Error: err.Error()})
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return json.Marshal(WhoisResult{RegistrableDomain: etld1, Error: fmt.Sprintf("rdap status %d", resp.StatusCode)})
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return json.Marshal(WhoisResult{RegistrableDomain: etld1, Error: err.Error()})
	}
	res, err := ParseRDAP(body, w.now())
	if err != nil {
		return json.Marshal(WhoisResult{RegistrableDomain: etld1, Error: "parse: " + err.Error()})
	}
	return json.Marshal(res)
}
