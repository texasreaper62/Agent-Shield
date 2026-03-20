// Package agentshieldprocessor implements an OpenTelemetry Collector processor
// that scans log and trace data for AI-specific security threats using Agent
// Shield detection patterns. It can annotate, drop, or log threatening telemetry.
package agentshieldprocessor

import (
	"errors"
	"fmt"
	"strings"
)

// Config holds the configuration for the Agent Shield processor.
type Config struct {
	// MinSeverity is the minimum threat severity to act on.
	// Valid values: "low", "medium", "high", "critical".
	MinSeverity string `mapstructure:"min_severity"`

	// Categories restricts scanning to specific threat categories.
	// An empty list means all categories are scanned.
	Categories []string `mapstructure:"categories"`

	// ScanAttributes lists which log body or span attribute keys to scan.
	// If empty, the processor scans all string-valued attributes and the
	// log body.
	ScanAttributes []string `mapstructure:"scan_attributes"`

	// Action determines what happens when a threat is detected.
	// Valid values:
	//   "log"      - emit a warning log but pass the data through unchanged
	//   "drop"     - remove the threatening log record or span
	//   "annotate" - add threat metadata attributes and pass through
	Action string `mapstructure:"action"`
}

// createDefaultConfig returns a Config populated with sensible defaults.
func createDefaultConfig() *Config {
	return &Config{
		MinSeverity:    "low",
		Categories:     nil,
		ScanAttributes: nil,
		Action:         "log",
	}
}

// Validate checks the processor configuration for errors.
func (cfg *Config) Validate() error {
	validSeverities := map[string]bool{
		"low": true, "medium": true, "high": true, "critical": true,
	}
	sev := strings.ToLower(cfg.MinSeverity)
	if !validSeverities[sev] {
		return fmt.Errorf("min_severity must be one of low, medium, high, critical; got %q", cfg.MinSeverity)
	}

	validActions := map[string]bool{
		"log": true, "drop": true, "annotate": true,
	}
	action := strings.ToLower(cfg.Action)
	if !validActions[action] {
		return fmt.Errorf("action must be one of log, drop, annotate; got %q", cfg.Action)
	}

	if cfg.ScanAttributes != nil {
		for _, attr := range cfg.ScanAttributes {
			if strings.TrimSpace(attr) == "" {
				return errors.New("scan_attributes must not contain empty strings")
			}
		}
	}

	return nil
}
