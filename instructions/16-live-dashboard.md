# 16. Live Dashboard (Real-Time Threat Monitoring)

## Overview

The live dashboard provides a real-time WebSocket-driven UI for monitoring Agent Shield threat detections. It runs as a standalone Node.js server with zero external dependencies.

Located in `dashboard-live/`.

---

## Quick Start

```bash
cd dashboard-live
node -e "
  const { ThreatStreamServer } = require('./server');
  const server = new ThreatStreamServer({ port: 8080 });
  server.start();
"
```

Open `http://localhost:8080` in your browser to see the dashboard.

---

## Architecture

The dashboard uses a custom RFC 6455 WebSocket implementation (no `ws` or `socket.io` dependency).

```
┌─────────────┐     HTTP      ┌──────────────────┐     WebSocket     ┌─────────────┐
│ Agent Shield │ ──ingest()──→ │ ThreatStreamServer│ ──broadcast()──→ │  Browser UI │
│   (scanner)  │              │   (server.js)     │                  │ (index.html) │
└─────────────┘              └──────────────────┘                  └─────────────┘
```

### Components

- **ThreatStreamServer** — HTTP + WebSocket server
- **index.html** — Single-page dashboard UI
- **WebSocket protocol** — RFC 6455 with custom frame encode/decode

---

## Integration with Agent Shield

### Programmatic Ingestion

```javascript
const { AgentShield } = require('agent-shield');
const { ThreatStreamServer } = require('./dashboard-live/server');

const shield = new AgentShield({ blocking: true });
const dashboard = new ThreatStreamServer({ port: 8080 });

await dashboard.start();

// After each scan, feed results to the dashboard
const result = await shield.scan(userInput);
dashboard.ingestScan({
  threats: result.detections,
  latency: result.latency,
  blocked: result.blocked
});
```

### HTTP Ingestion

POST scan results from any language or service:

```bash
curl -X POST http://localhost:8080/api/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "threats": [{"category": "prompt_injection", "severity": "high", "message": "Injection detected"}],
    "latency": 4.2,
    "blocked": true
  }'
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard HTML page |
| GET | `/api/stats` | Current statistics JSON |
| GET | `/api/threats` | Recent threat history (last 100) |
| POST | `/api/ingest` | Ingest a scan result |
| WS | `/ws` | WebSocket stream |

---

## WebSocket Messages

### Server → Client

**`init`** — Sent on connection with current state:
```json
{
  "type": "init",
  "data": {
    "stats": { "totalScans": 1000, "totalThreats": 42, "..." },
    "recentThreats": [{ "id": "...", "category": "...", "..." }]
  }
}
```

**`threat`** — Real-time threat event:
```json
{
  "type": "threat",
  "data": {
    "id": "abc123",
    "timestamp": 1710936000000,
    "category": "prompt_injection",
    "severity": "critical",
    "message": "Injection attempt detected",
    "blocked": true
  }
}
```

**`stats`** — Periodic stats update (every 1 second):
```json
{
  "type": "stats",
  "data": {
    "totalScans": 1500,
    "totalThreats": 55,
    "detectionRate": "3.67",
    "avgLatency": 4.2,
    "threatsByCategory": { "prompt_injection": 30, "jailbreak": 15 },
    "threatsBySeverity": { "critical": 5, "high": 20, "medium": 25, "low": 5 },
    "throughputPerSecond": [12, 15, 8, 20, "..."],
    "connectedClients": 3,
    "uptime": 3600
  }
}
```

---

## Configuration

```javascript
const server = new ThreatStreamServer({
  port: 8080,        // HTTP/WS port
  maxClients: 100,   // Max concurrent WebSocket connections
  historySize: 1000  // Threat history ring buffer size
});
```

---

## Running Tests

```bash
cd dashboard-live
npm test
```

The test suite covers WebSocket handshake, frame encoding/decoding, threat ingestion, stats computation, and client lifecycle.

---

## Next Steps

- [Getting Started](./01-getting-started.md) — Basic Agent Shield setup
- [Production Deployment](./09-production-deployment.md) — Logging, monitoring, webhooks
- [Enterprise & Infrastructure](./12-enterprise-and-infrastructure.md) — K8s, Terraform, OTel
