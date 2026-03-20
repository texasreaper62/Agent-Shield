// Package agentshieldreceiver implements an OpenTelemetry Collector receiver
// that exposes an HTTP endpoint for scanning text with Agent Shield. Each
// detected threat is emitted as an OTel log record.
package agentshieldreceiver

import (
	"errors"
	"fmt"
	"strings"
)

// Config holds the configuration for the Agent Shield receiver.
type Config struct {
	// Port is the TCP port the HTTP scan endpoint listens on.
	Port int `mapstructure:"port"`

	// Path is the URL path that accepts scan requests (e.g., "/scan").
	Path string `mapstructure:"path"`

	// MinSeverity is the minimum threat severity to emit as log records.
	// Valid values: "low", "medium", "high", "critical".
	MinSeverity string `mapstructure:"min_severity"`

	// BlockOnThreat controls whether the receiver returns an HTTP 403
	// when threats are detected, effectively blocking the request.
	BlockOnThreat bool `mapstructure:"block_on_threat"`
}

// createDefaultConfig returns a Config populated with sensible defaults.
func createDefaultConfig() *Config {
	return &Config{
		Port:          8888,
		Path:          "/scan",
		MinSeverity:   "low",
		BlockOnThreat: false,
	}
}

// Validate checks the receiver configuration for errors. It returns a
// non-nil error if the configuration is invalid.
func (cfg *Config) Validate() error {
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", cfg.Port)
	}

	if cfg.Path == "" {
		return errors.New("path must not be empty")
	}

	if !strings.HasPrefix(cfg.Path, "/") {
		return fmt.Errorf("path must start with '/', got %q", cfg.Path)
	}

	validSeverities := map[string]bool{
		"low": true, "medium": true, "high": true, "critical": true,
	}
	sev := strings.ToLower(cfg.MinSeverity)
	if !validSeverities[sev] {
		return fmt.Errorf("min_severity must be one of low, medium, high, critical; got %q", cfg.MinSeverity)
	}

	return nil
}
