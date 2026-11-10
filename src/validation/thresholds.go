package validation

import (
	"os"
	"strconv"
	"strings"
)

// defaultUpstreamTolerancePercent is how far stored records may be from the recorded upstream total.
const defaultUpstreamTolerancePercent = 1

// envFloat reads a non-negative number from the environment, or returns fallback when unset or invalid.
func envFloat(name string, fallback float64) float64 {
	if value, err := strconv.ParseFloat(os.Getenv(name), 64); err == nil && value >= 0 {
		return value
	}
	return fallback
}

// sourceEnvFloat prefers NAME_<SOURCE>, then NAME, then fallback.
func sourceEnvFloat(name, source string, fallback float64) float64 {
	return envFloat(name+"_"+strings.ToUpper(source), envFloat(name, fallback))
}

// upstreamTolerancePercent reads KNOWLEDGE_GATE_UPSTREAM_TOLERANCE_PERCENT[_<SOURCE>].
func upstreamTolerancePercent(source string) float64 {
	return sourceEnvFloat("KNOWLEDGE_GATE_UPSTREAM_TOLERANCE_PERCENT", source, defaultUpstreamTolerancePercent)
}

// envList reads a comma-separated list from the environment, or returns fallback when unset.
func envList(name string, fallback []string) []string {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	var values []string
	for _, value := range strings.Split(raw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	return values
}
