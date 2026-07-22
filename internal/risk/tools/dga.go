package tools

import (
	"context"
	"encoding/json"
	"math"
	"strings"
)

// DGAResult is the dga_score return contract.
type DGAResult struct {
	DGAProbability  float64 `json:"dga_probability"`
	ShannonEntropy  float64 `json:"shannon_entropy"`
	Length          int     `json:"length"`
	ConsonantRatio  float64 `json:"consonant_ratio"`
	DigitRatio      float64 `json:"digit_ratio"`
	DictionaryMatch bool    `json:"dictionary_match"`
}

// ScoreDGA scores whether a domain's second-level label looks algorithmically
// generated. Pure lexical computation (no network): Shannon entropy + character
// ratios + a pronounceability heuristic for dictionary_match. DGA detection is
// inherently heuristic; a wordlist/ML model can replace the dictionary heuristic
// behind this same result shape.
func ScoreDGA(etld1 string) DGAResult {
	// The second-level label carries the DGA signal (e.g. "acme-portal" of
	// acme-portal.co, "kq3v9x7zmwp" of kq3v9x7zmwp.com).
	label := strings.SplitN(strings.ToLower(etld1), ".", 2)[0]
	label = strings.ReplaceAll(label, "-", "")
	r := DGAResult{Length: len(label)}
	if label == "" {
		return r
	}

	var letters, consonants, digits, vowels int
	freq := map[rune]int{}
	for _, c := range label {
		freq[c]++
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'a' && c <= 'z':
			letters++
			if strings.ContainsRune("aeiou", c) {
				vowels++
			} else {
				consonants++
			}
		}
	}
	n := float64(len(label))
	for _, cnt := range freq {
		p := float64(cnt) / n
		r.ShannonEntropy -= p * math.Log2(p)
	}
	r.ShannonEntropy = math.Round(r.ShannonEntropy*100) / 100
	if letters > 0 {
		r.ConsonantRatio = math.Round(float64(consonants)/float64(letters)*100) / 100
	}
	r.DigitRatio = math.Round(float64(digits)/n*100) / 100

	// Pronounceability heuristic proxy for dictionary_match: has vowels, no long
	// consonant run, moderate entropy.
	r.DictionaryMatch = vowels > 0 && maxConsonantRun(label) <= 4 && r.ShannonEntropy < 3.6

	// DGA probability — weighted combination, judgment layer refines it upstream.
	entN := clamp01((r.ShannonEntropy-2.5)/2.0) // ~2.5..4.5 → 0..1
	p := 0.40*entN + 0.25*r.ConsonantRatio + 0.20*r.DigitRatio + 0.15*boolf(!r.DictionaryMatch)
	if r.DictionaryMatch {
		p *= 0.5
	}
	if r.Length <= 6 {
		p *= 0.7 // short labels are noisy; be less confident
	}
	r.DGAProbability = math.Round(clamp01(p)*100) / 100
	return r
}

func maxConsonantRun(label string) int {
	best, cur := 0, 0
	for _, c := range label {
		if c >= 'a' && c <= 'z' && !strings.ContainsRune("aeiou", c) {
			cur++
			if cur > best {
				best = cur
			}
		} else {
			cur = 0
		}
	}
	return best
}

func clamp01(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}

func boolf(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// dgaTool adapts ScoreDGA to the Tool interface.
type dgaTool struct{}

func NewDGATool() Tool { return dgaTool{} }

func (dgaTool) Name() string { return "dga_score" }

func (dgaTool) Definition() ToolDef {
	return ToolDef{
		Name: "dga_score",
		Description: "Scores whether the domain label looks algorithmically generated (DGA). " +
			"Returns dga_probability 0.0-1.0 plus the lexical features behind it. High " +
			"probability with no dictionary_match is a strong C2 signal.",
		InputSchema: domainInputSchema,
	}
}

func (dgaTool) Run(_ context.Context, _, etld1 string) (json.RawMessage, error) {
	return json.Marshal(ScoreDGA(etld1))
}
