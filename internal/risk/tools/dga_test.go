package tools

import "testing"

// The DGA scorer is the one enrichment signal that's pure math — lock its ends:
// dictionary-word / brand labels score low, random high-entropy C2-style labels
// score high, and the lexical features are sane.
func TestScoreDGA(t *testing.T) {
	low := []string{"google.com", "acme-portal.co", "microsoft.com", "shopee.com"}
	for _, d := range low {
		r := ScoreDGA(d)
		if r.DGAProbability >= 0.5 {
			t.Errorf("%s: dga_probability %.2f should be low (<0.5)", d, r.DGAProbability)
		}
		if !r.DictionaryMatch && d == "google.com" {
			t.Errorf("google should read as dictionary-like")
		}
	}

	high := []string{"kq3v9x7zmwp.com", "xkzqvwjhbdfg.net", "a8f3k9d2m7q1x.info"}
	for _, d := range high {
		r := ScoreDGA(d)
		if r.DGAProbability < 0.5 {
			t.Errorf("%s: dga_probability %.2f should be high (>=0.5)", d, r.DGAProbability)
		}
		if r.DictionaryMatch {
			t.Errorf("%s should NOT read as a dictionary word", d)
		}
	}

	// Feature sanity on an obvious random label.
	r := ScoreDGA("xkzqvwjhbdfg.net")
	if r.ShannonEntropy < 3.0 || r.ConsonantRatio < 0.8 {
		t.Errorf("random label features look wrong: %+v", r)
	}
}
