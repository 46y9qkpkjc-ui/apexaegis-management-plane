package risk

import "testing"

// The score→decision bands are the contract (allow 0-24, monitor 25-64, deny
// 65-100). Lock the boundaries so a refactor can't silently shift them.
func TestDecisionForScore(t *testing.T) {
	cases := []struct {
		score int
		want  Decision
	}{
		{0, DecisionAllow}, {24, DecisionAllow},
		{25, DecisionMonitor}, {64, DecisionMonitor},
		{65, DecisionDeny}, {100, DecisionDeny},
	}
	for _, c := range cases {
		if got := DecisionForScore(c.score); got != c.want {
			t.Errorf("DecisionForScore(%d) = %q, want %q", c.score, got, c.want)
		}
	}
}
