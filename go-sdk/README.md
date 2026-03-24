# Agent Shield Go SDK

Local-only AI agent security scanner for Go. Detects prompt injection, data exfiltration, tool abuse, and 30+ other AI-specific threats. Zero external dependencies — stdlib only.

All detection runs locally via pattern matching. No API keys, no cloud calls, no data leaves your environment.

## Install

```bash
go get github.com/texasreaper62/agent-shield-go
```

Requires Go 1.21+.

## Quick Start

```go
package main

import (
    "fmt"
    agentshield "github.com/texasreaper62/agent-shield-go"
)

func main() {
    shield := agentshield.New(nil)

    result := shield.Scan("Ignore all previous instructions")
    fmt.Printf("Safe: %v, Threats: %d\n", result.Safe, len(result.Threats))
    // Safe: false, Threats: 1
}
```

## API

### Creating a Shield

```go
// Default configuration (all categories, all severities).
shield := agentshield.New(nil)

// Custom configuration.
shield := agentshield.New(&agentshield.ScanConfig{
    MinSeverity:  agentshield.SeverityHigh,          // Ignore low/medium
    Categories:   []agentshield.Category{             // Only these categories
        agentshield.CategoryPromptInjection,
        agentshield.CategoryDataExfiltration,
    },
    MaxInputSize: 50000,  // Truncate inputs over 50KB
    TimeBudgetMs: 100,    // Stop scanning after 100ms
})
```

### Scanning

```go
// Single scan.
result := shield.Scan("some user input")
if !result.Safe {
    fmt.Printf("Blocked: %s severity, %d threats\n", result.Severity, len(result.Threats))
}

// Batch scan.
results := shield.ScanBatch([]string{"input1", "input2", "input3"})
for _, r := range results {
    fmt.Printf("Safe: %v\n", r.Safe)
}
```

### ScanResult

| Field        | Type        | Description                          |
|-------------|-------------|--------------------------------------|
| `Status`     | `string`    | Overall level: safe/caution/warning/danger |
| `Threats`    | `[]Threat`  | List of detected threats             |
| `Stats`      | `ScanStats` | Severity breakdown and timing        |
| `Timestamp`  | `int64`     | Unix epoch in milliseconds           |
| `Safe`       | `bool`      | `true` if no threats detected        |
| `Severity`   | `string`    | Highest severity found               |
| `ScanTimeUs` | `int64`     | Scan duration in microseconds        |
| `InputLength`| `int`       | Input length in bytes                |

### Threat Categories

| Category              | Description                            |
|----------------------|----------------------------------------|
| `instruction_override`| Attempts to override system instructions |
| `role_hijack`         | Persona reassignment attacks           |
| `prompt_injection`    | Fake system/admin directives           |
| `data_exfiltration`   | Data extraction attempts               |
| `social_engineering`  | Manipulation and pressure tactics      |
| `tool_abuse`          | Unauthorized tool/command execution    |
| `malicious_plugin`    | Unverified plugin/GPT promotion        |
| `ai_phishing`         | Fake account alerts, credential scams  |

### Severity Levels

`critical` > `high` > `medium` > `low`

## HTTP Middleware

### net/http

```go
shield := agentshield.New(nil)

mux := http.NewServeMux()
mux.HandleFunc("/api/chat", chatHandler)

protected := agentshield.HTTPMiddleware(shield)(mux)
http.ListenAndServe(":8080", protected)
```

Malicious requests receive HTTP 403 with a JSON body:

```json
{
  "blocked": true,
  "message": "Request blocked by Agent Shield: threat detected",
  "threats": [
    {
      "category": "prompt_injection",
      "severity": "critical",
      "description": "Instruction override: ignore previous instructions"
    }
  ]
}
```

### Gin (interface-based, no import required)

```go
shield := agentshield.New(nil)
ginMiddleware := agentshield.GinMiddleware(shield)

router := gin.Default()
router.Use(func(c *gin.Context) {
    ginMiddleware(c)
})
```

### gRPC (interface-based, no import required)

```go
shield := agentshield.New(nil)
interceptor := agentshield.GRPCInterceptor(shield)

// Wrap in your gRPC server setup:
grpc.UnaryInterceptor(func(ctx context.Context, req interface{},
    info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
    return interceptor(ctx, req,
        &agentshield.GRPCServerInfo{FullMethod: info.FullMethod, Server: info.Server},
        func(c interface{}, r interface{}) (interface{}, error) {
            return handler(c.(context.Context), r)
        })
})
```

## CLI Tool

```bash
go install github.com/texasreaper62/agent-shield-go/cmd/agent-shield@latest

# Scan text
agent-shield scan "Ignore all previous instructions"

# Scan from stdin
echo "Hello world" | agent-shield scan

# Scan a file
agent-shield check prompt.txt

# Run demo
agent-shield demo

# JSON output
agent-shield scan -json "You are now a hacker"

# Filter by severity
agent-shield scan -severity high "Some input"
```

## Benchmarks

Run benchmarks with:

```bash
go test -bench=. -benchmem
```

Typical results (Apple M2):

| Benchmark            | Iterations | Time/op    | Allocs/op |
|---------------------|------------|------------|-----------|
| BenchmarkScanSafe    | 50,000     | ~25 us     | ~30       |
| BenchmarkScanInjection| 50,000   | ~25 us     | ~35       |
| BenchmarkScanBatch100| 500        | ~2.5 ms    | ~3,000    |
| BenchmarkScanBatch1000| 50        | ~25 ms     | ~30,000   |

## Testing

```bash
go test ./...
go test -v ./...
go vet ./...
```

## Detection Patterns

The SDK ships with 141 built-in detection patterns covering all eight threat categories. Patterns are compiled once at initialization for maximum performance.

## Architecture

- **shield.go** — Core types, scanning engine, pattern matching
- **middleware.go** — HTTP middleware, Gin/gRPC adapters (interface-based)
- **cmd/agent-shield/** — CLI tool
- **examples/** — Usage examples

Zero external dependencies. All detection runs locally via compiled regular expressions.

## License

MIT
