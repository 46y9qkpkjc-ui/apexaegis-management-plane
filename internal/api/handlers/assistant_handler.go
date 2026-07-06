package handlers

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/zcp/management-plane/internal/assistant"
)

// AssistantHandler exposes the voice/agent admin capabilities to the web UI and
// the (server-side) Claude agent: explain why a user is denied a destination, and
// grant a user access. Backed by the deterministic assistant.Service.
type AssistantHandler struct {
	svc    *assistant.Service
	agent  *assistant.Agent        // nil when ANTHROPIC_API_KEY is unset
	voice  *assistant.VoiceService // nil when DEEPGRAM/ELEVENLABS keys are unset
	logger *zap.Logger
}

func NewAssistantHandler(svc *assistant.Service, agent *assistant.Agent, voice *assistant.VoiceService, logger *zap.Logger) *AssistantHandler {
	return &AssistantHandler{svc: svc, agent: agent, voice: voice, logger: logger}
}

type explainReq struct {
	UserQuery   string `json:"user_query"`
	Destination string `json:"destination"`
}

type grantReq struct {
	UserQuery   string `json:"user_query"`
	Destination string `json:"destination"`
	Scope       string `json:"scope"`
	URLCategory string `json:"url_category"`
	Confirm     bool   `json:"confirm"`
}

// ExplainAccess — POST /api/v1/admin/assistant/explain-access
func (h *AssistantHandler) ExplainAccess(c *gin.Context) {
	var req explainReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if strings.TrimSpace(req.UserQuery) == "" || strings.TrimSpace(req.Destination) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_query and destination are required"})
		return
	}
	res, err := h.svc.ExplainAccess(c.Request.Context(), req.UserQuery, req.Destination)
	if err != nil {
		h.logger.Error("explain-access", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "explain failed"})
		return
	}
	c.JSON(http.StatusOK, res)
}

// GrantAccess — POST /api/v1/admin/assistant/grant-access
func (h *AssistantHandler) GrantAccess(c *gin.Context) {
	var req grantReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if strings.TrimSpace(req.UserQuery) == "" || (strings.TrimSpace(req.Destination) == "" && strings.TrimSpace(req.URLCategory) == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_query and either destination or url_category are required"})
		return
	}
	res, err := h.svc.GrantAccess(c.Request.Context(), req.UserQuery, req.Destination,
		assistant.GrantOptions{Scope: req.Scope, URLCategory: req.URLCategory}, req.Confirm, author(c))
	if err != nil {
		h.logger.Error("grant-access", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "grant failed"})
		return
	}
	c.JSON(http.StatusOK, res)
}

// Bridge — POST /api/v1/admin/assistant/bridge
// Reconciles the AD-synced groups into native policy groups. Idempotent.
func (h *AssistantHandler) Bridge(c *gin.Context) {
	res, err := h.svc.Bridge(c.Request.Context())
	if err != nil {
		h.logger.Error("bridge", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "bridge failed"})
		return
	}
	c.JSON(http.StatusOK, res)
}

// SeedDemo — POST /api/v1/admin/assistant/seed-demo
// Bridges groups + creates the demo deny policy (Finance Users → prudential). Idempotent.
func (h *AssistantHandler) SeedDemo(c *gin.Context) {
	res, err := h.svc.SeedDemo(c.Request.Context(), author(c))
	if err != nil {
		h.logger.Error("seed-demo", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "seed failed"})
		return
	}
	c.JSON(http.StatusOK, res)
}

type chatReq struct {
	Messages []assistant.ChatMessage `json:"messages"`
}

// Chat — POST /api/v1/admin/assistant/chat
// Runs one Claude agent turn over the conversation and returns the reply.
func (h *AssistantHandler) Chat(c *gin.Context) {
	if h.agent == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "assistant agent not configured (set ANTHROPIC_API_KEY)"})
		return
	}
	var req chatReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if len(req.Messages) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "messages are required"})
		return
	}
	res, err := h.agent.Chat(c.Request.Context(), req.Messages, author(c))
	if err != nil {
		h.logger.Error("assistant chat", zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "assistant is unavailable"})
		return
	}
	c.JSON(http.StatusOK, res)
}

// Voice — POST /api/v1/admin/assistant/voice (multipart)
// Fields: audio (file), history (JSON array of {role,content}, optional).
// Transcribes → runs the agent → synthesizes the reply.
func (h *AssistantHandler) Voice(c *gin.Context) {
	if h.voice == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "voice not configured (set DEEPGRAM_API_KEY and ELEVENLABS_API_KEY)"})
		return
	}
	fileHeader, err := c.FormFile("audio")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "audio file is required (multipart field 'audio')"})
		return
	}
	f, err := fileHeader.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot read audio"})
		return
	}
	defer f.Close()
	audio, err := io.ReadAll(io.LimitReader(f, 25<<20)) // 25 MB cap
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot read audio"})
		return
	}
	var history []assistant.ChatMessage
	if hs := strings.TrimSpace(c.PostForm("history")); hs != "" {
		_ = json.Unmarshal([]byte(hs), &history)
	}
	res, err := h.voice.HandleTurn(c.Request.Context(), audio, fileHeader.Header.Get("Content-Type"), history, author(c))
	if err != nil {
		h.logger.Error("assistant voice", zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "voice pipeline failed"})
		return
	}
	c.JSON(http.StatusOK, res)
}

// Speak — POST /api/v1/admin/assistant/speak  {text} → {audio_base64}
func (h *AssistantHandler) Speak(c *gin.Context) {
	if h.voice == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "voice not configured"})
		return
	}
	var req struct {
		Text string `json:"text"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Text) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "text is required"})
		return
	}
	audio, err := h.voice.Speak(c.Request.Context(), req.Text)
	if err != nil {
		h.logger.Error("assistant speak", zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "tts failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"audio_base64": base64.StdEncoding.EncodeToString(audio), "audio_mime": "audio/mpeg"})
}

func author(c *gin.Context) string {
	if id := c.GetString("user_id"); id != "" {
		return id
	}
	return "apex-assistant"
}
