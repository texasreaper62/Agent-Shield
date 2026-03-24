package agentshieldprocessor

import (
	"context"
	"fmt"
)

// componentType is the unique identifier for this processor.
const componentType = "agent_shield_processor"

// ComponentType returns the string identifier for this processor component.
func ComponentType() string {
	return componentType
}

// LogData represents a batch of log records flowing through the pipeline.
type LogData struct {
	Records []LogRecord
}

// LogRecord represents a single log record in the processing pipeline.
type LogRecord struct {
	SeverityText   string
	SeverityNumber int
	Body           string
	Attributes     map[string]string
	TraceID        string
}

// TraceData represents a batch of traces flowing through the pipeline.
type TraceData struct {
	Spans []Span
}

// Span represents a single span in the processing pipeline.
type Span struct {
	Name       string
	TraceID    string
	SpanID     string
	Attributes map[string]string
	Events     []SpanEvent
}

// SpanEvent represents an event attached to a span.
type SpanEvent struct {
	Name       string
	Attributes map[string]string
}

// NextLogsConsumer is the next component in the logs pipeline.
type NextLogsConsumer interface {
	ConsumeLogs(ctx context.Context, logs LogData) error
}

// NextTracesConsumer is the next component in the traces pipeline.
type NextTracesConsumer interface {
	ConsumeTraces(ctx context.Context, traces TraceData) error
}

// Factory creates Agent Shield processor instances.
type Factory struct {
	typ           string
	defaultConfig func() *Config
}

// NewFactory returns a Factory that can create Agent Shield processors.
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

// CreateDefaultConfig returns a new default Config for this processor.
func (f *Factory) CreateDefaultConfig() *Config {
	return f.defaultConfig()
}

// CreateLogsProcessor creates a processor that scans log records for threats.
func (f *Factory) CreateLogsProcessor(
	ctx context.Context,
	cfg *Config,
	next NextLogsConsumer,
) (*agentShieldProcessor, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config must not be nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	if next == nil {
		return nil, fmt.Errorf("next logs consumer must not be nil")
	}

	p := newProcessor(cfg)
	p.nextLogs = next
	return p, nil
}

// CreateTracesProcessor creates a processor that scans trace spans for threats.
func (f *Factory) CreateTracesProcessor(
	ctx context.Context,
	cfg *Config,
	next NextTracesConsumer,
) (*agentShieldProcessor, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config must not be nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	if next == nil {
		return nil, fmt.Errorf("next traces consumer must not be nil")
	}

	p := newProcessor(cfg)
	p.nextTraces = next
	return p, nil
}
