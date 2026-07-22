// Package tools implements the six deterministic enrichment backends the domain
// risk agent calls (contract §4). Each tool takes a domain and returns a JSON
// result matching its return contract; the agent reasons over those results and
// emits the final verdict. Tools are real integrations — RDAP/WHOIS, threat
// intel, geo/ASN, lexical DGA, NRD, NOD — behind this interface so the
// credentialed ones can be swapped/stubbed independently.
package tools

import (
	"context"
	"encoding/json"
)

// ToolDef is an Anthropic Messages-API tool definition (name + description +
// input_schema) — what the agent advertises to Claude.
type ToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// Tool is one enrichment backend. Run is given the FQDN and the registrable
// eTLD+1 (already normalized by the caller) so a tool can pick whichever it
// needs without re-parsing the public suffix list.
type Tool interface {
	Name() string
	Definition() ToolDef
	Run(ctx context.Context, fqdn, etld1 string) (json.RawMessage, error)
}

// domainInputSchema is the shared input schema — every tool takes {domain}.
var domainInputSchema = json.RawMessage(`{
  "type": "object", "additionalProperties": false,
  "properties": { "domain": { "type": "string", "description": "FQDN or eTLD+1" } },
  "required": ["domain"]
}`)
