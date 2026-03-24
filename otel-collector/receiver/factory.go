package agentshieldreceiver

import (
	"context"
	"fmt"
)

// componentType is the unique identifier for this receiver.
const componentType = "agent_shield_receiver"

// ComponentType returns the string identifier for this receiver component.
func ComponentType() string {
	return componentType
}

// LogConsumer is an interface for consuming log records.
// This simulates the OTel plog.LogsConsumer interface.
type LogConsumer interface {
	// ConsumeLogs receives a batch of log records.
	ConsumeLogs(ctx context.Context, logs LogBatch) error
}

// LogBatch represents a batch of log records.
type LogBatch struct {
	Records []LogRecord
}

// LogRecord represents a single OTel-style log record.
type LogRecord struct {
	// SeverityText is the human-readable severity (e.g., "WARN", "ERROR").
	SeverityText string
	// SeverityNumber is the numeric severity level per OTel spec.
	SeverityNumber int
	// Body is the log message body.
	Body string
	// Attributes holds key-value metadata.
	Attributes map[string]string
	// TraceID links the log to a trace.
	TraceID string
}

// Host represents the OTel Collector host environment.
// This simulates the component.Host interface.
type Host interface {
	// ReportFatalError reports an unrecoverable error.
	ReportFatalError(err error)
}

// Factory creates Agent Shield receiver instances.
type Factory struct {
	typ           string
	defaultConfig func() *Config
}

// NewFactory returns a Factory that can create Agent Shield receivers.
func NewFactory() *Factory {
	return &Factory{
		typ:           componentType,
		defaultConfig: createDefaultConfig,
	}
}

// Type returns the component type identifier.
func (f *Factory) Type() string {
	return f.typ
}

// CreateDefaultConfig returns a new default Config for this receiver.
func (f *Factory) CreateDefaultConfig() *Config {
	return f.defaultConfig()
}

// CreateLogsReceiver creates a new agentShieldReceiver that emits threat
// detections as log records to the given consumer.
func (f *Factory) CreateLogsReceiver(
	ctx context.Context,
	cfg *Config,
	consumer LogConsumer,
) (*agentShieldReceiver, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config must not be nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	if consumer == nil {
		return nil, fmt.Errorf("log consumer must not be nil")
	}

	return newReceiver(cfg, consumer), nil
}
