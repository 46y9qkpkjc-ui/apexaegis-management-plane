package posture

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestZtaVerdict(t *testing.T) {
	// overall >= threshold => compliant
	v := ztaVerdict("dev1", 72, 50, 80, 65)
	if !v.Compliant || v.Score != 72 || v.Source != "crowdstrike-zta" {
		t.Fatalf("unexpected verdict %+v", v)
	}
	if v.Signals["os_score"] != "80" || v.Signals["sensor_score"] != "65" {
		t.Fatalf("signals not mapped: %+v", v.Signals)
	}
	// below threshold => non-compliant
	if ztaVerdict("dev2", 40, 50, 40, 40).Compliant {
		t.Fatal("score below threshold marked compliant")
	}
}

func TestCrowdStrikeDisabledIsNoop(t *testing.T) {
	c := NewCrowdStrikeZTA(CrowdStrikeConfig{}, nil) // no creds
	if c.Enabled() {
		t.Fatal("connector reports enabled without creds")
	}
	got, err := c.Fetch(context.Background(), "org1")
	if err != nil || got != nil {
		t.Fatalf("disabled connector should no-op, got (%v,%v)", got, err)
	}
}

type fakeConnector struct{ verdicts []Verdict }

func (fakeConnector) Name() string { return "fake" }
func (f fakeConnector) Fetch(context.Context, string) ([]Verdict, error) {
	return f.verdicts, nil
}

func TestRunnerPollsAndSaves(t *testing.T) {
	var mu sync.Mutex
	saved := map[string]Verdict{}
	save := func(_ context.Context, _ string, v Verdict) error {
		mu.Lock()
		saved[v.DeviceID] = v
		mu.Unlock()
		return nil
	}
	orgs := func(context.Context) ([]string, error) { return []string{"org1"}, nil }
	conn := fakeConnector{verdicts: []Verdict{
		{DeviceID: "d1", Compliant: true, Score: 90, Source: "fake"},
		{DeviceID: "", Compliant: true},       // skipped (no device id)
		{DeviceID: "d2", Compliant: false, Score: 10},
	}}
	r := NewRunner(save, orgs, time.Hour, nil, conn)

	ctx, cancel := context.WithCancel(context.Background())
	r.pollOnce(ctx) // exercise one cycle deterministically
	cancel()

	mu.Lock()
	defer mu.Unlock()
	if len(saved) != 2 {
		t.Fatalf("saved %d verdicts, want 2 (empty device id skipped)", len(saved))
	}
	if saved["d2"].Compliant {
		t.Fatal("d2 should be non-compliant")
	}
}
