package assistant

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"go.uber.org/zap"
)

// Agent is the Claude tool-use loop behind the voice/agent admin. It exposes the
// deterministic Service methods as tools and drives a manual loop so grants can be
// gated behind explicit confirmation (a dedicated-tool concern the runner can't do).
type Agent struct {
	svc    *Service
	client anthropic.Client
	model  anthropic.Model
	logger *zap.Logger
}

func NewAgent(svc *Service, apiKey string, logger *zap.Logger) *Agent {
	return &Agent{
		svc:    svc,
		client: anthropic.NewClient(option.WithAPIKey(apiKey)),
		model:  anthropic.ModelClaudeOpus4_8,
		logger: logger,
	}
}

// ChatMessage is one turn of conversation as seen by the client (text only).
type ChatMessage struct {
	Role    string `json:"role"` // "user" | "assistant"
	Content string `json:"content"`
}

// ToolCall records a tool the agent invoked during a turn (for audit / UI).
type ToolCall struct {
	Name   string          `json:"name"`
	Input  json.RawMessage `json:"input"`
	Result json.RawMessage `json:"result"`
}

// ChatResult is the agent's reply plus the tools it ran.
type ChatResult struct {
	Reply     string     `json:"reply"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
}

const systemPrompt = `You are Apex, the voice-enabled security administrator for the ApexAegis multi-tenant Zero Trust platform. You assist human administrators across many tenants (clients). Your capabilities:

1. Investigate a block — why a user's request was blocked. Use get_block_evidence (it resolves the user's tenant and returns the blocking policy name AND id, the matching logs, a sanctioned alternative, and links). Use explain_access for a lighter allow/deny check.
2. Investigate a category change — why a site that used to work suddenly stopped, and which tenants are affected. Use explain_category_impact.
3. Surface correlated SOC / CVE events — use list_security_events (CVE, affected OS/kernel, inspection action, affected clients and which have it pushed + verified).
4. Grant access — allow a user to reach a destination. Use grant_access.
5. Email a summary — use send_email.

When you report a result, always name the user, list their group names, name the policy involved AND its policy id, and — when the tool returns a policy_link and logs_link — read out or include those links so the administrator can view the policy and logs. When you name affected clients, use their tenant names. Keep spoken replies short and natural; they may be read aloud.

AFTER you give any explanation (a block, a category change, or a SOC event), always ASK the administrator whether you should send the same summary as an email. If they say yes: get the recipient address if you don't have it, call send_email with confirm=false to preview, tell them what will be sent, and only call send_email with confirm=true after they confirm. Put the explanation plus the policy and log links in the email body. Never send without explicit confirmation.

Before you grant, gather the details that change what gets created — ask ONE short clarifying question when any of these is unclear, then proceed:
- Scope: should this apply to just this user, or their whole group? Default to the group, but ask when it is ambiguous. Pass scope="user" or scope="group".
- Destination: a single site (e.g. dbs.com.sg), or a whole URL category (e.g. the Financial Services category)? If they mean a category, pass url_category instead of a single destination.

Granting access changes live security policy, so you MUST confirm before applying:
- First call grant_access with confirm=false to preview. Then tell the administrator exactly what will change — the user, the scope (user or which groups), the destination, and the policy name — and ask them to confirm.
- If the preview returns a warning (for example, the user has a non-compliant device), relay that warning to the administrator before they confirm.
- Only after the administrator explicitly confirms in a later message may you call grant_access with confirm=true. Never set confirm=true in the same turn as the preview.

If a name matches more than one user, ask which one. If no user matches, say so plainly. Do not invent groups, policies, destinations, or categories — rely only on the tool results.`

// Chat runs one assistant turn over the given conversation history and returns the
// reply. The final message in history should be the user's latest message.
func (a *Agent) Chat(ctx context.Context, history []ChatMessage, author string) (*ChatResult, error) {
	msgs := make([]anthropic.MessageParam, 0, len(history)+4)
	for _, m := range history {
		if strings.EqualFold(m.Role, "assistant") {
			msgs = append(msgs, anthropic.NewAssistantMessage(anthropic.NewTextBlock(m.Content)))
		} else {
			msgs = append(msgs, anthropic.NewUserMessage(anthropic.NewTextBlock(m.Content)))
		}
	}

	tools := a.tools()
	result := &ChatResult{}

	// Bounded loop: model may call tools several times before its final answer.
	for iter := 0; iter < 6; iter++ {
		resp, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
			Model:     a.model,
			MaxTokens: 8192,
			System:    []anthropic.TextBlockParam{{Text: systemPrompt}},
			Thinking:  anthropic.ThinkingConfigParamUnion{OfAdaptive: &anthropic.ThinkingConfigAdaptiveParam{}},
			Messages:  msgs,
			Tools:     tools,
		})
		if err != nil {
			return nil, fmt.Errorf("claude: %w", err)
		}
		msgs = append(msgs, resp.ToParam())

		var turnText strings.Builder
		var toolResults []anthropic.ContentBlockParamUnion
		for _, block := range resp.Content {
			switch v := block.AsAny().(type) {
			case anthropic.TextBlock:
				turnText.WriteString(v.Text)
			case anthropic.ToolUseBlock:
				raw := []byte(v.JSON.Input.Raw())
				out, isErr := a.dispatch(ctx, v.Name, raw, author)
				result.ToolCalls = append(result.ToolCalls, ToolCall{Name: v.Name, Input: raw, Result: out})
				toolResults = append(toolResults, anthropic.NewToolResultBlock(block.ID, string(out), isErr))
			}
		}

		if resp.StopReason != anthropic.StopReasonToolUse {
			result.Reply = strings.TrimSpace(turnText.String())
			return result, nil
		}
		msgs = append(msgs, anthropic.NewUserMessage(toolResults...))
	}

	result.Reply = "I wasn't able to complete that in a reasonable number of steps — please try rephrasing."
	return result, nil
}

func (a *Agent) dispatch(ctx context.Context, name string, input []byte, author string) (json.RawMessage, bool) {
	switch name {
	case "find_user":
		var in struct {
			Query string `json:"query"`
		}
		_ = json.Unmarshal(input, &in)
		users, err := a.svc.FindUser(ctx, in.Query)
		if err != nil {
			return errJSON(err), true
		}
		return mustJSON(map[string]any{"matches": users, "count": len(users)}), false

	case "explain_access":
		var in struct {
			UserQuery   string `json:"user_query"`
			Destination string `json:"destination"`
		}
		_ = json.Unmarshal(input, &in)
		res, err := a.svc.ExplainAccess(ctx, in.UserQuery, in.Destination)
		if err != nil {
			return errJSON(err), true
		}
		return mustJSON(res), false

	case "grant_access":
		var in struct {
			UserQuery   string `json:"user_query"`
			Destination string `json:"destination"`
			Scope       string `json:"scope"`
			URLCategory string `json:"url_category"`
			Confirm     bool   `json:"confirm"`
		}
		_ = json.Unmarshal(input, &in)
		res, err := a.svc.GrantAccess(ctx, in.UserQuery, in.Destination,
			GrantOptions{Scope: in.Scope, URLCategory: in.URLCategory}, in.Confirm, author)
		if err != nil {
			return errJSON(err), true
		}
		return mustJSON(res), false

	case "get_block_evidence":
		var in struct {
			UserQuery   string `json:"user_query"`
			Destination string `json:"destination"`
		}
		_ = json.Unmarshal(input, &in)
		res, err := a.svc.BlockEvidence(ctx, in.UserQuery, in.Destination)
		if err != nil {
			return errJSON(err), true
		}
		return mustJSON(res), false

	case "explain_category_impact":
		var in struct {
			Domain string `json:"domain"`
		}
		_ = json.Unmarshal(input, &in)
		res, err := a.svc.CategoryImpact(ctx, in.Domain)
		if err != nil {
			return errJSON(err), true
		}
		return mustJSON(res), false

	case "list_security_events":
		res, err := a.svc.SecurityEvents(ctx)
		if err != nil {
			return errJSON(err), true
		}
		return mustJSON(map[string]any{"events": res, "count": len(res)}), false

	case "send_email":
		var in struct {
			To      string `json:"to"`
			Subject string `json:"subject"`
			Body    string `json:"body"`
			Confirm bool   `json:"confirm"`
		}
		_ = json.Unmarshal(input, &in)
		res, err := a.svc.SendEmail(ctx, in.To, in.Subject, in.Body, in.Confirm)
		if err != nil {
			return errJSON(err), true
		}
		return mustJSON(res), false

	default:
		return errJSON(fmt.Errorf("unknown tool %q", name)), true
	}
}

func (a *Agent) tools() []anthropic.ToolUnionParam {
	strProp := func(desc string) map[string]any {
		return map[string]any{"type": "string", "description": desc}
	}
	findUser := anthropic.ToolParam{
		Name:        "find_user",
		Description: anthropic.String("Look up directory (AD) users by name, UPN, or sAMAccountName. Use to disambiguate when a name might match more than one person."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]any{"query": strProp("Name, UPN, or sAMAccountName, e.g. 'Mr. Mark' or 'anderson'")},
			Required:   []string{"query"},
		},
	}
	explain := anthropic.ToolParam{
		Name:        "explain_access",
		Description: anthropic.String("Explain whether a user can reach a destination and, if a policy applies, which policy decides it and why. Read-only."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]any{
				"user_query":  strProp("The user, e.g. 'Mr. Mark' or 'mark'"),
				"destination": strProp("URL or hostname, e.g. https://www.prudential.com.sg/ or prudential.com.sg"),
			},
			Required: []string{"user_query", "destination"},
		},
	}
	grant := anthropic.ToolParam{
		Name:        "grant_access",
		Description: anthropic.String("Grant a user access by creating an allow policy, placed above any deny that would block it. Scope it to the user's whole group (default) or just the user. Allow a single host (destination) OR a whole URL category (url_category). Call confirm=false first to preview; only call confirm=true after the administrator explicitly confirms."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]any{
				"user_query":   strProp("The user, e.g. 'Mr. Anderson'"),
				"destination":  strProp("Single URL or hostname to allow, e.g. dbs.com.sg. Omit when granting a whole url_category."),
				"scope":        map[string]any{"type": "string", "enum": []string{"user", "group"}, "description": "'group' (default) allows the user's whole group; 'user' allows only this person."},
				"url_category": strProp("Optional: allow a whole URL category by name (e.g. 'Financial Services') instead of a single destination."),
				"confirm":      map[string]any{"type": "boolean", "description": "false = preview only (default). true = apply — only after explicit admin confirmation."},
			},
			Required: []string{"user_query"},
		},
	}
	blockEvidence := anthropic.ToolParam{
		Name:        "get_block_evidence",
		Description: anthropic.String("Investigate why a user's request was blocked. Resolves the user's tenant, returns the blocking policy (name AND id), the matching DNS/traffic logs, a sanctioned alternative if one exists, and deep-links to view the policy and the logs. Prefer this over explain_access when the admin asks why someone is blocked or wants to see the logs. Read-only."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]any{
				"user_query":  strProp("The user, e.g. 'Frank' or 'frank@dbs.example'"),
				"destination": strProp("Optional site/domain to narrow to, e.g. dropbox.com"),
			},
			Required: []string{"user_query"},
		},
	}
	categoryImpact := anthropic.ToolParam{
		Name:        "explain_category_impact",
		Description: anthropic.String("Explain a threat-intel URL-category reclassification for a domain (what it changed from and to, the source, and when) and list the tenants now blocking it. Use when a site that used to work suddenly stopped, or the admin asks who is affected by a category change. Read-only."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]any{"domain": strProp("The domain, e.g. aspire.com")},
			Required:   []string{"domain"},
		},
	}
	securityEvents := anthropic.ToolParam{
		Name:        "list_security_events",
		Description: anthropic.String("List correlated SOC / CVE security events: the CVE, affected OS/kernel, the inspection action taken, the affected clients with their internal resources, and which clients have the remediation pushed and verified. Use when the admin asks about correlated SOC events or incidents. Read-only."),
		InputSchema: anthropic.ToolInputSchemaParam{Properties: map[string]any{}},
	}
	sendEmail := anthropic.ToolParam{
		Name:        "send_email",
		Description: anthropic.String("Email a summary (e.g. the explanation you just gave) to an administrator. Call confirm=false first to preview; only call confirm=true after the administrator explicitly confirms and you have a recipient address. Include the policy/log links in the body."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]any{
				"to":      strProp("Recipient email address"),
				"subject": strProp("Email subject"),
				"body":    strProp("Email body — the explanation plus the policy and log links"),
				"confirm": map[string]any{"type": "boolean", "description": "false = preview (default). true = send — only after explicit admin confirmation."},
			},
			Required: []string{"to", "subject", "body"},
		},
	}
	return []anthropic.ToolUnionParam{
		{OfTool: &findUser},
		{OfTool: &explain},
		{OfTool: &grant},
		{OfTool: &blockEvidence},
		{OfTool: &categoryImpact},
		{OfTool: &securityEvents},
		{OfTool: &sendEmail},
	}
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return errJSON(err)
	}
	return b
}

func errJSON(err error) json.RawMessage {
	b, _ := json.Marshal(map[string]string{"error": err.Error()})
	return b
}
