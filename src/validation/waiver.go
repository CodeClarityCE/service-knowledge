package validation

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

// Waiver records the failing checks a gate run let pass, and why.
type Waiver struct {
	Reason string   `json:"reason"`
	Checks []string `json:"checks"`
}

// waiverRules are the check patterns from KNOWLEDGE_GATE_WAIVE and the reason from
// KNOWLEDGE_GATE_WAIVE_REASON. A pattern is "<source>.<check>" or "<source>.*".
type waiverRules struct {
	patterns []string
	reason   string
}

// readWaiver reads the waiver for a gate over sources. Only source checks can be waived,
// never the structural ones, and a waiver without a reason is refused.
func readWaiver(sources []string) (waiverRules, error) {
	patterns := envList("KNOWLEDGE_GATE_WAIVE", nil)
	if len(patterns) == 0 {
		return waiverRules{}, nil
	}
	reason := strings.TrimSpace(os.Getenv("KNOWLEDGE_GATE_WAIVE_REASON"))
	if reason == "" {
		return waiverRules{}, fmt.Errorf("KNOWLEDGE_GATE_WAIVE needs KNOWLEDGE_GATE_WAIVE_REASON")
	}
	for _, pattern := range patterns {
		source, check, found := strings.Cut(pattern, ".")
		if !found || check == "" || !slices.Contains(sources, source) {
			return waiverRules{}, fmt.Errorf("cannot waive %q: use <source>.<check> or <source>.* for a gated source", pattern)
		}
	}
	return waiverRules{patterns: patterns, reason: reason}, nil
}

// covers reports whether a pattern waives the named check.
func (w waiverRules) covers(name string) bool {
	for _, pattern := range w.patterns {
		if prefix, ok := strings.CutSuffix(pattern, "*"); ok && strings.HasPrefix(name, prefix) {
			return true
		}
		if pattern == name {
			return true
		}
	}
	return false
}

// apply marks the failing checks the waiver covers and returns the waiver to record, if any.
func (w waiverRules) apply(checks []Check) *Waiver {
	var waived []string
	for i := range checks {
		if !checks[i].Pass && w.covers(checks[i].Name) {
			checks[i].Waived = true
			waived = append(waived, checks[i].Name)
		}
	}
	if len(waived) == 0 {
		return nil
	}
	slices.Sort(waived)
	return &Waiver{Reason: w.reason, Checks: waived}
}
