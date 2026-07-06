package assistant

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// VoiceService chains speech-to-text (Deepgram) → the Claude agent → text-to-speech
// (ElevenLabs). Keys live server-side (SSM), so the mobile app only records and plays
// audio and never sees a provider credential.
type VoiceService struct {
	agent  *Agent
	stt    *Deepgram
	tts    *ElevenLabs
	logger *zap.Logger
}

func NewVoiceService(agent *Agent, deepgramKey, elevenKey, elevenVoiceID string, logger *zap.Logger) *VoiceService {
	return &VoiceService{
		agent:  agent,
		stt:    NewDeepgram(deepgramKey),
		tts:    NewElevenLabs(elevenKey, elevenVoiceID),
		logger: logger,
	}
}

// VoiceResult is what a single spoken turn returns to the app.
type VoiceResult struct {
	Transcript  string     `json:"transcript"`
	Reply       string     `json:"reply"`
	AudioBase64 string     `json:"audio_base64"` // mp3
	AudioMIME   string     `json:"audio_mime"`
	ToolCalls   []ToolCall `json:"tool_calls,omitempty"`
}

// HandleTurn transcribes the audio, runs one agent turn over history+transcript,
// and synthesizes the reply. history is the prior conversation (text only).
func (v *VoiceService) HandleTurn(ctx context.Context, audio []byte, contentType string, history []ChatMessage, author string) (*VoiceResult, error) {
	transcript, err := v.stt.Transcribe(ctx, audio, contentType)
	if err != nil {
		return nil, fmt.Errorf("transcribe: %w", err)
	}
	if strings.TrimSpace(transcript) == "" {
		return &VoiceResult{Transcript: "", Reply: "I didn't catch that — could you say it again?"}, nil
	}

	turns := append(history, ChatMessage{Role: "user", Content: transcript})
	chat, err := v.agent.Chat(ctx, turns, author)
	if err != nil {
		return nil, fmt.Errorf("agent: %w", err)
	}

	res := &VoiceResult{Transcript: transcript, Reply: chat.Reply, ToolCalls: chat.ToolCalls}
	if audioOut, err := v.tts.Synthesize(ctx, chat.Reply); err != nil {
		// Non-fatal: return the text so the app can still display (and speak locally).
		v.logger.Warn("tts synth failed", zap.Error(err))
	} else {
		res.AudioBase64 = base64.StdEncoding.EncodeToString(audioOut)
		res.AudioMIME = "audio/mpeg"
	}
	return res, nil
}

// Speak synthesizes arbitrary text to mp3 (for the /speak endpoint).
func (v *VoiceService) Speak(ctx context.Context, text string) ([]byte, error) {
	return v.tts.Synthesize(ctx, text)
}

// ── Deepgram (STT) ───────────────────────────────────────────────────────────

type Deepgram struct {
	key  string
	http *http.Client
}

func NewDeepgram(key string) *Deepgram {
	return &Deepgram{key: key, http: &http.Client{Timeout: 30 * time.Second}}
}

// Transcribe posts audio to Deepgram's pre-recorded endpoint and returns the text.
// Deepgram auto-detects the container/codec, so contentType may be a best-effort hint.
func (d *Deepgram) Transcribe(ctx context.Context, audio []byte, contentType string) (string, error) {
	const url = "https://api.deepgram.com/v1/listen?model=nova-2&smart_format=true&punctuate=true"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(audio))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Token "+d.key)
	if contentType == "" {
		contentType = "audio/*"
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := d.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("deepgram %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		Results struct {
			Channels []struct {
				Alternatives []struct {
					Transcript string `json:"transcript"`
				} `json:"alternatives"`
			} `json:"channels"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("deepgram decode: %w", err)
	}
	if len(out.Results.Channels) == 0 || len(out.Results.Channels[0].Alternatives) == 0 {
		return "", nil
	}
	return strings.TrimSpace(out.Results.Channels[0].Alternatives[0].Transcript), nil
}

// ── ElevenLabs (TTS) ─────────────────────────────────────────────────────────

// DefaultElevenVoiceID ("Rachel") is a Voice-Library voice — usable only on paid
// plans via the API. When ELEVENLABS_VOICE_ID is unset we auto-resolve a premade
// voice the account can actually use (free plans can't call library voices).
const DefaultElevenVoiceID = "21m00Tcm4TlvDq8ikWAM"

type ElevenLabs struct {
	key      string
	voiceID  string // explicit override from env; "" ⇒ auto-resolve from the account
	resolved string
	mu       sync.Mutex
	http     *http.Client
}

func NewElevenLabs(key, voiceID string) *ElevenLabs {
	return &ElevenLabs{key: key, voiceID: strings.TrimSpace(voiceID), http: &http.Client{Timeout: 30 * time.Second}}
}

// resolveVoice returns the explicit override voice if set, otherwise the first
// premade (free-accessible) voice from the account, cached after the first lookup.
func (e *ElevenLabs) resolveVoice(ctx context.Context) (string, error) {
	if e.voiceID != "" {
		return e.voiceID, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.resolved != "" {
		return e.resolved, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.elevenlabs.io/v1/voices", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("xi-api-key", e.key)
	resp, err := e.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("elevenlabs voices %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		Voices []struct {
			VoiceID  string `json:"voice_id"`
			Category string `json:"category"`
		} `json:"voices"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	for _, v := range out.Voices {
		if v.Category == "premade" {
			e.resolved = v.VoiceID
			break
		}
	}
	if e.resolved == "" && len(out.Voices) > 0 {
		e.resolved = out.Voices[0].VoiceID
	}
	if e.resolved == "" {
		return "", fmt.Errorf("no ElevenLabs voices available for this account")
	}
	return e.resolved, nil
}

// Synthesize converts text to mp3 audio via ElevenLabs (turbo model for low latency).
func (e *ElevenLabs) Synthesize(ctx context.Context, text string) ([]byte, error) {
	if strings.TrimSpace(text) == "" {
		return nil, fmt.Errorf("empty text")
	}
	voiceID, err := e.resolveVoice(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve voice: %w", err)
	}
	url := "https://api.elevenlabs.io/v1/text-to-speech/" + voiceID + "?output_format=mp3_44100_128"
	payload, _ := json.Marshal(map[string]any{
		"text":     text,
		"model_id": "eleven_turbo_v2_5",
		"voice_settings": map[string]any{
			"stability":        0.5,
			"similarity_boost": 0.75,
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("xi-api-key", e.key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "audio/mpeg")

	resp, err := e.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return nil, fmt.Errorf("elevenlabs %d: %s", resp.StatusCode, string(msg))
	}
	return io.ReadAll(resp.Body)
}
