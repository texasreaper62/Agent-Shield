package agentshieldprocessor

import (
	"context"
	"log"
	"strings"

	"github.com/texasreaper62/agent-shield-otel/scanner"
)

// agentShieldProcessor scans telemetry data (logs and traces) for
// AI-specific security threats and takes a configured action.
type agentShieldProcessor struct {
	config     *Config
	scanner    *scanner.Scanner
	nextLogs   NextLogsConsumer
	nextTraces NextTracesConsumer
}

// newProcessor constructs a new agentShieldProcessor.
func newProcessor(cfg *Config) *agentShieldProcessor {
	categories := make([]scanner.Category, len(cfg.Categories))
	for i, c := range cfg.Categories {
		categories[i] = scanner.Category(c)
	}
	scanCfg := &scanner.Config{
		MinSeverity: scanner.ParseSeverity(cfg.MinSeverity),
		Categories:  categories,
	}
	return &agentShieldProcessor{
		config:  cfg,
		scanner: scanner.New(scanCfg),
	}
}

// ProcessLogs scans each log record's body and specified attributes for
// threats. Depending on the configured action, it annotates, drops, or
// logs a warning for threatening records.
func (p *agentShieldProcessor) ProcessLogs(ctx context.Context, logs LogData) (LogData, error) {
	action := strings.ToLower(p.config.Action)
	filtered := make([]LogRecord, 0, len(logs.Records))

	for _, rec := range logs.Records {
		threats := p.scanLogRecord(rec)

		if len(threats) == 0 {
			filtered = append(filtered, rec)
			continue
		}

		switch action {
		case "drop":
			log.Printf("[Agent Shield] Dropping log record: %d threat(s) detected", len(threats))
			// Record is omitted from the output.

		case "annotate":
			rec = p.annotateLogRecord(rec, threats)
			filtered = append(filtered, rec)

		case "log":
			for _, t := range threats {
				log.Printf("[Agent Shield] Threat in log record: category=%s severity=%s desc=%q",
					t.Category, t.Severity, t.Description)
			}
			filtered = append(filtered, rec)

		default:
			// Unknown action; pass through.
			filtered = append(filtered, rec)
		}
	}

	result := LogData{Records: filtered}

	if p.nextLogs != nil {
		return result, p.nextLogs.ConsumeLogs(ctx, result)
	}
	return result, nil
}

// ProcessTraces scans each span's attributes and events for threats.
// Depending on the configured action, it annotates, drops, or logs
// a warning for threatening spans.
func (p *agentShieldProcessor) ProcessTraces(ctx context.Context, traces TraceData) (TraceData, error) {
	action := strings.ToLower(p.config.Action)
	filtered := make([]Span, 0, len(traces.Spans))

	for _, span := range traces.Spans {
		threats := p.scanSpan(span)

		if len(threats) == 0 {
			filtered = append(filtered, span)
			continue
		}

		switch action {
		case "drop":
			log.Printf("[Agent Shield] Dropping span %q: %d threat(s) detected", span.Name, len(threats))
			// Span is omitted from the output.

		case "annotate":
			span = p.annotateSpan(span, threats)
			filtered = append(filtered, span)

		case "log":
			for _, t := range threats {
				log.Printf("[Agent Shield] Threat in span %q: category=%s severity=%s desc=%q",
					span.Name, t.Category, t.Severity, t.Description)
			}
			filtered = append(filtered, span)

		default:
			filtered = append(filtered, span)
		}
	}

	result := TraceData{Spans: filtered}

	if p.nextTraces != nil {
		return result, p.nextTraces.ConsumeTraces(ctx, result)
	}
	return result, nil
}

// scanLogRecord scans a log record's body and configured attributes.
func (p *agentShieldProcessor) scanLogRecord(rec LogRecord) []scanner.Threat {
	var allThreats []scanner.Threat

	// Always scan the body.
	if rec.Body != "" {
		result := p.scanner.Scan(rec.Body)
		allThreats = append(allThreats, result.Threats...)
	}

	// Scan specified attributes, or all attributes if none are specified.
	attrs := p.attributesToScan(rec.Attributes)
	for _, val := range attrs {
		result := p.scanner.Scan(val)
		allThreats = append(allThreats, result.Threats...)
	}

	return deduplicateThreats(allThreats)
}

// scanSpan scans a span's attributes and events.
func (p *agentShieldProcessor) scanSpan(span Span) []scanner.Threat {
	var allThreats []scanner.Threat

	// Scan span attributes.
	attrs := p.attributesToScan(span.Attributes)
	for _, val := range attrs {
		result := p.scanner.Scan(val)
		allThreats = append(allThreats, result.Threats...)
	}

	// Scan span events and their attributes.
	for _, evt := range span.Events {
		if evt.Name != "" {
			result := p.scanner.Scan(evt.Name)
			allThreats = append(allThreats, result.Threats...)
		}
		evtAttrs := p.attributesToScan(evt.Attributes)
		for _, val := range evtAttrs {
			result := p.scanner.Scan(val)
			allThreats = append(allThreats, result.Threats...)
		}
	}

	return deduplicateThreats(allThreats)
}

// attributesToScan returns the attribute values that should be scanned.
// If ScanAttributes is configured, only those keys are returned.
// Otherwise, all string-valued attributes are returned.
func (p *agentShieldProcessor) attributesToScan(attrs map[string]string) map[string]string {
	if attrs == nil {
		return nil
	}

	if len(p.config.ScanAttributes) == 0 {
		return attrs
	}

	result := make(map[string]string)
	for _, key := range p.config.ScanAttributes {
		if val, ok := attrs[key]; ok {
			result[key] = val
		}
	}
	return result
}

// annotateLogRecord adds threat metadata attributes to a log record.
func (p *agentShieldProcessor) annotateLogRecord(rec LogRecord, threats []scanner.Threat) LogRecord {
	if rec.Attributes == nil {
		rec.Attributes = make(map[string]string)
	}

	rec.Attributes["agent_shield.threat.detected"] = "true"
	rec.Attributes["agent_shield.threat.count"] = formatInt(len(threats))

	// Add the highest-severity threat details.
	highest := highestSeverityThreat(threats)
	rec.Attributes["agent_shield.threat.category"] = string(highest.Category)
	rec.Attributes["agent_shield.threat.severity"] = highest.Severity.String()
	rec.Attributes["agent_shield.threat.description"] = highest.Description

	// Add all categories as a comma-separated list.
	rec.Attributes["agent_shield.threat.categories"] = joinCategories(threats)

	return rec
}

// annotateSpan adds threat metadata attributes to a span.
func (p *agentShieldProcessor) annotateSpan(span Span, threats []scanner.Threat) Span {
	if span.Attributes == nil {
		span.Attributes = make(map[string]string)
	}

	span.Attributes["agent_shield.threat.detected"] = "true"
	span.Attributes["agent_shield.threat.count"] = formatInt(len(threats))

	highest := highestSeverityThreat(threats)
	span.Attributes["agent_shield.threat.category"] = string(highest.Category)
	span.Attributes["agent_shield.threat.severity"] = highest.Severity.String()
	span.Attributes["agent_shield.threat.description"] = highest.Description

	span.Attributes["agent_shield.threat.categories"] = joinCategories(threats)

	return span
}

// deduplicateThreats removes duplicate threats by pattern name.
func deduplicateThreats(threats []scanner.Threat) []scanner.Threat {
	if len(threats) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	unique := make([]scanner.Threat, 0, len(threats))
	for _, t := range threats {
		if !seen[t.Pattern] {
			seen[t.Pattern] = true
			unique = append(unique, t)
		}
	}
	return unique
}

// highestSeverityThreat returns the threat with the highest severity.
func highestSeverityThreat(threats []scanner.Threat) scanner.Threat {
	if len(threats) == 0 {
		return scanner.Threat{}
	}

	best := threats[0]
	for _, t := range threats[1:] {
		if t.Severity >= best.Severity {
			best = t
		}
	}
	return best
}

// joinCategories returns a comma-separated list of unique categories.
func joinCategories(threats []scanner.Threat) string {
	seen := make(map[scanner.Category]bool)
	var cats []string
	for _, t := range threats {
		if !seen[t.Category] {
			seen[t.Category] = true
			cats = append(cats, string(t.Category))
		}
	}
	return strings.Join(cats, ",")
}

// formatInt converts an int to a string without importing strconv.
func formatInt(n int) string {
	if n == 0 {
		return "0"
	}
	digits := make([]byte, 0, 10)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	if neg {
		digits = append(digits, '-')
	}
	// Reverse.
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}
