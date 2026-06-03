package handlers

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/db"
	"gopkg.in/yaml.v3"
)

// AgentHandler handles client agent requests (policy downloads, config syncs).
type AgentHandler struct {
	policyStore *db.PolicyStore
	logger      *zap.Logger
}

// NewAgentHandler creates a new AgentHandler.
func NewAgentHandler(policyStore *db.PolicyStore, logger *zap.Logger) *AgentHandler {
	return &AgentHandler{
		policyStore: policyStore,
		logger:      logger,
	}
}

// Policy represents a split tunnel policy rule.
type Policy struct {
	ID      string   `yaml:"id"`
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`      // domain, ip, port, app
	Patterns []string `yaml:"patterns"`
	Action  string   `yaml:"action"`    // tunnel, bypass
	SSLMode string   `yaml:"ssl_mode"`  // disabled, cert-only, full
	Enabled bool     `yaml:"enabled"`
}

// PolicyConfig represents the full policy file structure.
type PolicyConfig struct {
	Version  string   `yaml:"version"`
	Policies []Policy `yaml:"policies"`
}

// GetPolicies returns split tunnel policies as YAML for the desktop-client/agent.
//
// Endpoint: GET /api/v1/agent/policies
//
// Response: YAML-formatted policy file with split tunnel rules
//
// Example response:
//   version: "1"
//   policies:
//     - id: "prudential-bypass"
//       name: "Prudential Singapore"
//       type: "domain"
//       patterns:
//         - "*.prudential.com.sg"
//       action: "bypass"
//       ssl_mode: "disabled"
//       enabled: true
func (h *AgentHandler) GetPolicies(c *gin.Context) {
	h.logger.Info("agent: requesting split tunnel policies")

	// Build default policies for now (future: fetch from DB based on user/group)
	policies := h.buildDefaultPolicies()

	// Marshal to YAML
	config := PolicyConfig{
		Version:  "1",
		Policies: policies,
	}

	yamlData, err := yaml.Marshal(config)
	if err != nil {
		h.logger.Error("agent: failed to marshal policies to YAML",
			zap.Error(err))
		c.JSON(500, gin.H{"error": "failed to marshal policies"})
		return
	}

	// Return YAML response
	c.Header("Content-Type", "application/yaml")
	c.Data(200, "application/yaml", yamlData)
}

// buildDefaultPolicies returns the default set of split tunnel policies.
//
// These policies are returned to all agents until per-group policies are
// implemented via IDP integration.
func (h *AgentHandler) buildDefaultPolicies() []Policy {
	return []Policy{
		{
			ID:      "prudential-bypass",
			Name:    "Prudential Singapore",
			Type:    "domain",
			Patterns: []string{
				"*.prudential.com.sg",
				"prudential.com.sg",
			},
			Action:  "bypass",
			SSLMode: "disabled",
			Enabled: true,
		},
		{
			ID:      "dropbox-tunnel",
			Name:    "Dropbox",
			Type:    "domain",
			Patterns: []string{
				"*.dropbox.com",
				"dropbox.com",
				"*.dropboxusercontent.com",
			},
			Action:  "tunnel",
			SSLMode: "cert-only",
			Enabled: true,
		},
	}
}
