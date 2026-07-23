package risk

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/risk/tools"
)

// riskSystemPrompt is the domain-risk adjudicator prompt (contract §6). Static.
const riskSystemPrompt = `You are the domain-risk adjudicator for ApexAegis, a Zero-Trust (ZTNA/SSE) secure
web gateway. The enforcement point runs DEFAULT-DENY: a public domain a user's device is trying to
reach is not allowed until you return a verdict. You are consulted ONCE per domain (cached tenant-wide).
Device compliance and user identity are already established by the PDP — your job is strictly the
reputation and intent of the DOMAIN. Decide allow / monitor / deny and call emit_verdict exactly once.

TOOLS — deterministic enrichment. Call only what you need (two to four targeted calls is typical; do
NOT call everything by reflex). The high-value combination is age + reputation + DGA + hosting; add
NRD/NOD checks when age or novelty is the deciding factor.

WEIGH COMBINATIONS, not single signals:
  - newly-registered AND DGA-like AND high-abuse/bulletproof hosting AND no reputation -> likely C2/phishing. Deny.
  - newly-registered or newly-observed with thin reputation and nothing else bad -> may be a legitimate new
    service OR a staged threat; you can't yet tell. Prefer MONITOR over a hard deny.
  - new domain, real registrant, dictionary-word label, mainstream CDN/cloud hosting -> low score.
  - aged registration, good reputation, normal hosting -> allow.

DEFAULT-DENY BIAS: when signals are thin, missing, or contradictory, lean toward MONITOR, never allow.
Reserve ALLOW for positive evidence of benignity (established + good reputation, or top-list membership).
Reserve DENY for real evidence of harm (threat-feed hit, or a strong high-risk combination). monitor is the
safe middle — the flow proceeds under inspection and can be killed if it turns bad.

SCORE (0 benign .. 100 malicious), then let judgment override the band:
  0-24 -> allow    25-64 -> monitor    65-100 -> deny
Set confidence by how much independent signal actually agreed: low if tools failed or evidence is thin;
high only when multiple independent signals concur.

CACHE TTL (ttl_seconds): threat-feed/established deny or benign -> long (86400-604800); newly-registered or
newly-observed -> short (3600). top_factors: <=4 short phrases, most important first. rationale: 2-3 plain
sentences naming the concrete factors.`

// Agent is the Claude risk scorer (contract §3). On a cache MISS it runs an async
// agentic loop over the enrichment tools, gets an emit_verdict, and writes the
// tenant-global cache + the decision log. Never inline — off the packet path.
type Agent struct {
	client anthropic.Client
	model  anthropic.Model
	tools  []tools.Tool
	store  *Store
	logger *zap.Logger
}

// NewAgent builds the scorer. Currently wires the keyless real tools (DGA + RDAP
// whois); credentialed tools (reputation/geo/passive-DNS) register here as keys land.
func NewAgent(apiKey string, store *Store, logger *zap.Logger) *Agent {
	return &Agent{
		client: anthropic.NewClient(option.WithAPIKey(apiKey)),
		model:  anthropic.ModelClaudeOpus4_8,
		tools:  []tools.Tool{tools.NewDGATool(), tools.NewWhoisTool()},
		store:  store,
		logger: logger,
	}
}

// Score implements the Scorer seam — non-blocking; the loop runs in a goroutine
// so the PDP's cache-MISS path returns its provisional verdict immediately.
func (a *Agent) Score(_ context.Context, orgID, key string, scope KeyScope, ev DomainEvent) {
	go a.score(orgID, key, scope, ev)
}

func (a *Agent) score(orgID, key string, scope KeyScope, ev DomainEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	byName := map[string]tools.Tool{}
	toolDefs := make([]anthropic.ToolUnionParam, 0, len(a.tools)+1)
	for _, t := range a.tools {
		byName[t.Name()] = t
		toolDefs = append(toolDefs, anthropic.ToolUnionParam{OfTool: &anthropic.ToolParam{
			Name:        t.Name(),
			Description: anthropic.String(t.Definition().Description),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]any{"domain": map[string]any{"type": "string", "description": "FQDN or eTLD+1"}},
				Required:   []string{"domain"},
			},
		}})
	}
	toolDefs = append(toolDefs, emitVerdictToolDef())

	msgs := []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(fmt.Sprintf(
		"Adjudicate this public domain: %s (observed as %s, layer %s). Gather what you need, then call emit_verdict exactly once.",
		key, ev.Domain, ev.Layer)))}

	var verdict *EmitVerdict
	var toolsRan, toolsFailed []string
	for iter := 0; iter < 6 && verdict == nil; iter++ {
		resp, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
			Model:     a.model,
			MaxTokens: 4096,
			System:    []anthropic.TextBlockParam{{Text: riskSystemPrompt}},
			Messages:  msgs,
			Tools:     toolDefs,
		})
		if err != nil {
			a.logger.Warn("risk agent claude call failed", zap.Error(err), zap.String("domain", key))
			return
		}
		msgs = append(msgs, resp.ToParam())

		var toolResults []anthropic.ContentBlockParamUnion
		for _, block := range resp.Content {
			tu, ok := block.AsAny().(anthropic.ToolUseBlock)
			if !ok {
				continue
			}
			raw := []byte(tu.JSON.Input.Raw())
			if tu.Name == "emit_verdict" {
				var v EmitVerdict
				if err := json.Unmarshal(raw, &v); err != nil {
					toolResults = append(toolResults, anthropic.NewToolResultBlock(block.ID, "invalid verdict JSON", true))
					continue
				}
				verdict = &v
				toolResults = append(toolResults, anthropic.NewToolResultBlock(block.ID, "ok", false))
				continue
			}
			t, ok := byName[tu.Name]
			if !ok {
				toolResults = append(toolResults, anthropic.NewToolResultBlock(block.ID, "unknown tool", true))
				continue
			}
			out, rerr := t.Run(ctx, ev.Domain, key)
			if rerr != nil {
				toolsFailed = append(toolsFailed, tu.Name)
				toolResults = append(toolResults, anthropic.NewToolResultBlock(block.ID, rerr.Error(), true))
				continue
			}
			toolsRan = append(toolsRan, tu.Name)
			toolResults = append(toolResults, anthropic.NewToolResultBlock(block.ID, string(out), false))
		}
		if resp.StopReason != anthropic.StopReasonToolUse {
			break
		}
		if len(toolResults) > 0 {
			msgs = append(msgs, anthropic.NewUserMessage(toolResults...))
		}
	}

	if verdict == nil {
		a.logger.Warn("risk agent produced no verdict", zap.String("domain", key))
		return
	}
	verdict.Domain, verdict.SchemaVersion = key, SchemaVersion
	if len(verdict.ToolsRan) == 0 {
		verdict.ToolsRan = toolsRan
	}
	verdict.ToolsFailed = toolsFailed
	ttl := verdict.TTLSeconds
	if ttl <= 0 {
		ttl = 3600
	}
	expiresAt := time.Now().Add(time.Duration(ttl) * time.Second)

	if err := a.store.PutVerdict(ctx, orgID, key, scope, verdict, SourceAI, expiresAt); err != nil {
		a.logger.Error("risk agent cache write failed", zap.Error(err), zap.String("domain", key))
	}
	// Log the resolved AI decision (source=ai) — appears in the decision log.
	resolved := Verdict{Domain: ev.Domain, Key: key, KeyScope: scope,
		Decision: verdict.Decision, RiskScore: verdict.RiskScore, Source: SourceAI, Rationale: verdict.Rationale}
	_ = a.store.LogDecision(ctx, orgID, ev, resolved, verdict.Category)
	a.logger.Info("risk agent verdict",
		zap.String("domain", key), zap.String("decision", string(verdict.Decision)), zap.Int("score", verdict.RiskScore))
}

// emitVerdictToolDef is the terminal tool the agent calls with the final verdict.
func emitVerdictToolDef() anthropic.ToolUnionParam {
	return anthropic.ToolUnionParam{OfTool: &anthropic.ToolParam{
		Name:        "emit_verdict",
		Description: anthropic.String("Emit the final risk verdict for the domain. Call exactly once, at the end, after gathering what you need."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]any{
				"decision":   map[string]any{"type": "string", "enum": []string{"allow", "monitor", "deny"}},
				"risk_score": map[string]any{"type": "integer", "description": "0 benign .. 100 malicious"},
				"confidence": map[string]any{"type": "string", "enum": []string{"low", "medium", "high"}},
				"category":   map[string]any{"type": "string", "enum": []string{"benign", "newly_registered", "suspicious", "phishing", "malware", "c2", "anonymizer", "unknown"}},
				"signals": map[string]any{"type": "object", "properties": map[string]any{
					"domain_age":     map[string]any{"type": "string", "enum": []string{"nrd", "recent", "established", "unknown"}},
					"reputation":     map[string]any{"type": "string", "enum": []string{"good", "neutral", "poor", "malicious", "unknown"}},
					"dga_like":       map[string]any{"type": "boolean"},
					"geo_risk":       map[string]any{"type": "string", "enum": []string{"low", "medium", "high", "unknown"}},
					"newly_observed": map[string]any{"type": "boolean"},
				}},
				"top_factors": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "<=4 short phrases, most important first"},
				"rationale":   map[string]any{"type": "string", "description": "2-3 human sentences for the risk-score card"},
				"ttl_seconds": map[string]any{"type": "integer", "description": "cache lifetime; deny/established long, NRD short"},
			},
			Required: []string{"decision", "risk_score", "confidence", "category", "rationale", "ttl_seconds"},
		},
	}}
}
