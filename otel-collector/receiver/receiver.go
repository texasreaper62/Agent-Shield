package agentshieldreceiver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/texasreaper62/agent-shield-otel/scanner"
)

// scanRequest is the expected JSON body for scan requests.
type scanRequest struct {
	Text string `json:"text"`
}

// scanResponse is the JSON response returned by the scan endpoint.
type scanResponse struct {
	Threats  []scanner.Threat `json:"threats"`
	Blocked  bool             `json:"blocked"`
	Duration string           `json:"duration"`
}

// agentShieldReceiver is an OTel receiver that exposes an HTTP endpoint for
// scanning text. Each detected threat is converted to an OTel log record
// and forwarded to the configured consumer.
type agentShieldReceiver struct {
	config   *Config
	scanner  *scanner.Scanner
	consumer LogConsumer
	server   *http.Server
	mu       sync.Mutex
	started  bool
}

// newReceiver constructs a new agentShieldReceiver.
func newReceiver(cfg *Config, consumer LogConsumer) *agentShieldReceiver {
	scanCfg := &scanner.Config{
		MinSeverity: scanner.ParseSeverity(cfg.MinSeverity),
	}
	return &agentShieldReceiver{
		config:   cfg,
		scanner:  scanner.New(scanCfg),
		consumer: consumer,
	}
}

// Start begins the HTTP server and starts accepting scan requests.
// It implements the OTel component.Component Start method signature.
func (r *agentShieldReceiver) Start(ctx context.Context, host Host) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.started {
		return fmt.Errorf("receiver already started")
	}

	mux := http.NewServeMux()
	mux.HandleFunc(r.config.Path, r.handleScan)
	mux.HandleFunc("/health", r.handleHealth)

	addr := fmt.Sprintf(":%d", r.config.Port)
	r.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	r.started = true
	log.Printf("[Agent Shield] Receiver listening on %s%s", addr, r.config.Path)

	go func() {
		if err := r.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("[Agent Shield] HTTP server error: %v", err)
			if host != nil {
				host.ReportFatalError(err)
			}
		}
	}()

	return nil
}

// Shutdown gracefully stops the HTTP server.
// It implements the OTel component.Component Shutdown method signature.
func (r *agentShieldReceiver) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.started {
		return nil
	}

	r.started = false
	log.Printf("[Agent Shield] Receiver shutting down")

	if r.server != nil {
		return r.server.Shutdown(ctx)
	}
	return nil
}

// handleScan processes incoming scan requests. It reads the request body,
// runs the scanner, emits log records for each threat, and returns a JSON
// response summarizing the results.
func (r *agentShieldReceiver) handleScan(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body scanRequest
	dec := json.NewDecoder(req.Body)
	if err := dec.Decode(&body); err != nil {
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	defer req.Body.Close()

	if strings.TrimSpace(body.Text) == "" {
		http.Error(w, "text field must not be empty", http.StatusBadRequest)
		return
	}

	result := r.scanner.Scan(body.Text)

	// Convert each threat to an OTel log record and forward to the consumer.
	if len(result.Threats) > 0 {
		batch := r.threatsToLogBatch(result.Threats, body.Text)
		ctx := req.Context()
		if err := r.consumer.ConsumeLogs(ctx, batch); err != nil {
			log.Printf("[Agent Shield] Failed to emit log records: %v", err)
		}
	}

	// Build response.
	blocked := r.config.BlockOnThreat && result.IsThreat()
	resp := scanResponse{
		Threats:  result.Threats,
		Blocked:  blocked,
		Duration: result.Duration.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	if blocked {
		w.WriteHeader(http.StatusForbidden)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(resp); err != nil {
		log.Printf("[Agent Shield] Failed to encode response: %v", err)
	}
}

// handleHealth returns a simple health check response.
func (r *agentShieldReceiver) handleHealth(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok","component":"%s"}`, componentType)
}

// threatsToLogBatch converts scanner threats into an OTel LogBatch.
// Each threat becomes a separate log record with the original text hash
// as the TraceID for correlation.
func (r *agentShieldReceiver) threatsToLogBatch(threats []scanner.Threat, originalText string) LogBatch {
	// Use a hash of the original text as the TraceID so all threats
	// from the same scan are correlated.
	hash := sha256.Sum256([]byte(originalText))
	traceID := hex.EncodeToString(hash[:16]) // 16 bytes = 128-bit TraceID

	records := make([]LogRecord, 0, len(threats))
	for _, t := range threats {
		sevText, sevNum := otelSeverity(t.Severity)
		records = append(records, LogRecord{
			SeverityText:   sevText,
			SeverityNumber: sevNum,
			Body:           fmt.Sprintf("Agent Shield threat detected: %s", t.Description),
			TraceID:        traceID,
			Attributes: map[string]string{
				"agent_shield.threat.category":    string(t.Category),
				"agent_shield.threat.severity":    t.Severity.String(),
				"agent_shield.threat.description": t.Description,
				"agent_shield.threat.pattern":     t.Pattern,
				"agent_shield.threat.match":       t.Matched,
				"agent_shield.input_hash":         hex.EncodeToString(hash[:]),
			},
		})
	}

	return LogBatch{Records: records}
}

// otelSeverity maps scanner severity to OTel severity text and number.
// Follows the OpenTelemetry severity number specification.
func otelSeverity(sev scanner.Severity) (string, int) {
	switch sev {
	case scanner.SeverityCritical:
		return "FATAL", 21
	case scanner.SeverityHigh:
		return "ERROR", 17
	case scanner.SeverityMedium:
		return "WARN", 13
	case scanner.SeverityLow:
		return "INFO", 9
	default:
		return "INFO", 9
	}
}
