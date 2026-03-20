# Agent Shield — Live Dashboard

Real-time WebSocket streaming dashboard for monitoring Agent Shield threat detection. Zero external dependencies.

## Screenshots

The dashboard displays:

- **Metric Cards** — Total scans, active threats, detection rate, average latency
- **Throughput Chart** — Live SVG line chart showing scans/sec over the last 60 seconds
- **Threat Distribution** — Animated SVG donut chart breaking down threats by category
- **Top Categories** — Horizontal bar chart of most-attacked categories
- **Severity Heatmap** — Color-coded grid showing threat density by severity over time
- **Live Threat Feed** — Scrolling list with severity badges, timestamps, and categories
- **Connection Indicator** — Green (connected), yellow (reconnecting), red (disconnected)
- **Dark/Light Mode** — Toggle between themes

## Quick Start

### Standalone Server

```bash
node dashboard-live/server.js
# Dashboard available at http://localhost:8080
```

Set a custom port:

```bash
PORT=3000 node dashboard-live/server.js
```

### Integrated with Agent Shield

```js
const AgentShield = require('agent-shield');
const { DashboardIntegration } = require('./dashboard-live/integration');

const shield = new AgentShield({ blockByDefault: true });
const dashboard = new DashboardIntegration(shield, { port: 8080 });

await dashboard.start();
// Dashboard at http://localhost:8080

// All shield.scan() calls now stream to the dashboard automatically
const result = shield.scan('user input here');
```

### HTTP Ingest (No Shield Instance)

Send scan results directly via HTTP POST:

```bash
curl -X POST http://localhost:8080/api/ingest \
  -H 'Content-Type: application/json' \
  -d '{"latency": 12, "threats": [{"category": "prompt_injection", "severity": "critical", "message": "Injection detected"}]}'
```

## API Endpoints

| Method | Path          | Description                       |
|--------|---------------|-----------------------------------|
| GET    | `/`           | Dashboard HTML                    |
| GET    | `/api/stats`  | JSON scan statistics              |
| GET    | `/api/threats`| Recent threats (last 100)         |
| POST   | `/api/ingest` | Ingest a scan result              |
| WS     | `/ws`         | WebSocket stream                  |

## WebSocket Messages

### Server to Client

- `{ "type": "init", "data": { stats, recentThreats } }` — sent on connect
- `{ "type": "stats", "data": { ... } }` — periodic stats (every 1s)
- `{ "type": "threat", "data": { id, timestamp, category, severity, message } }` — real-time threat

### Client to Server

- `{ "type": "ping" }` — keepalive (server responds with pong)

## Architecture

```
server.js          — HTTP server + custom RFC 6455 WebSocket implementation
index.html         — Single-file dashboard (HTML + CSS + JS, no dependencies)
integration.js     — DashboardIntegration class wrapping AgentShield
test/test-server.js — Test suite
```

The WebSocket implementation handles:
- Sec-WebSocket-Accept header (SHA-1 of key + RFC 6455 magic string, base64)
- Frame encoding/decoding (text, binary, ping, pong, close)
- Masked client frames, unmasked server frames
- Fragmented frame buffering

## Running Tests

```bash
node dashboard-live/test/test-server.js
```

## Configuration

```js
const server = new ThreatStreamServer({
  port: 8080,        // HTTP/WS port
  maxClients: 100,   // Max concurrent WebSocket clients
  historySize: 1000  // Threat history ring buffer size
});
```

## Requirements

- Node.js >= 16
- Zero external dependencies
