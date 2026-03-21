'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const WS_MAGIC_STRING = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

/**
 * Real-time WebSocket streaming server for Agent Shield threat monitoring.
 * Zero external dependencies — uses Node.js http + custom RFC 6455 WebSocket implementation.
 */
class ThreatStreamServer {
  /**
   * @param {Object} config
   * @param {number} [config.port=8080]
   * @param {number} [config.maxClients=100]
   * @param {number} [config.historySize=1000]
   */
  constructor(config = {}) {
    this.port = config.port || 8080;
    this.maxClients = config.maxClients || 100;
    this.historySize = config.historySize || 1000;

    this._clients = new Set();
    this._server = null;
    this._statsInterval = null;

    // Statistics
    this._stats = {
      totalScans: 0,
      totalThreats: 0,
      threatsByCategory: {},
      threatsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
      latencyHistogram: [],
      throughputWindow: [],
      startTime: Date.now()
    };

    // Threat history ring buffer
    this._threatHistory = [];

    // Throughput rolling window (last 60 seconds)
    this._scanTimestamps = [];
  }

  /**
   * Start the HTTP + WebSocket server.
   * @returns {Promise<void>}
   */
  start() {
    return new Promise((resolve, reject) => {
      this._server = http.createServer((req, res) => {
        this._handleHTTP(req, res);
      });

      this._server.on('upgrade', (req, socket, head) => {
        this._handleUpgrade(req, socket);
      });

      this._server.on('error', reject);

      this._server.listen(this.port, () => {
        console.log(`[Agent Shield] Dashboard server listening on http://localhost:${this.port}`);
        this._startStatsBroadcast();
        resolve();
      });
    });
  }

  /**
   * Graceful shutdown.
   * @returns {Promise<void>}
   */
  stop() {
    return new Promise((resolve) => {
      if (this._statsInterval) {
        clearInterval(this._statsInterval);
        this._statsInterval = null;
      }

      // Close all WebSocket clients
      for (const client of this._clients) {
        try {
          client.socket.end();
        } catch (_) {
          // ignore
        }
      }
      this._clients.clear();

      if (this._server) {
        this._server.close(() => {
          console.log('[Agent Shield] Dashboard server stopped');
          this._server = null;
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  /**
   * Process a scan result from Agent Shield.
   * @param {Object} scanResult
   */
  ingestScan(scanResult) {
    const now = Date.now();
    this._stats.totalScans++;
    this._scanTimestamps.push(now);

    // Trim old timestamps (older than 60s)
    const cutoff = now - 60000;
    this._scanTimestamps = this._scanTimestamps.filter(t => t >= cutoff);

    // Track latency
    if (scanResult.latency !== null && scanResult.latency !== undefined) {
      this._stats.latencyHistogram.push(scanResult.latency);
      if (this._stats.latencyHistogram.length > this.historySize) {
        this._stats.latencyHistogram.shift();
      }
    }

    // Extract threats
    const threats = scanResult.threats || scanResult.detections || [];
    if (threats.length > 0) {
      this._stats.totalThreats += threats.length;

      for (const threat of threats) {
        const category = threat.category || threat.type || 'unknown';
        const severity = threat.severity || 'medium';

        this._stats.threatsByCategory[category] = (this._stats.threatsByCategory[category] || 0) + 1;
        if (this._stats.threatsBySeverity[severity] !== null && this._stats.threatsBySeverity[severity] !== undefined) {
          this._stats.threatsBySeverity[severity]++;
        }

        const threatEntry = {
          id: crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex'),
          timestamp: now,
          category,
          severity,
          message: threat.message || threat.description || `${category} detected`,
          input: threat.input ? threat.input.substring(0, 200) : undefined,
          blocked: scanResult.blocked || false
        };

        this._threatHistory.push(threatEntry);
        if (this._threatHistory.length > this.historySize) {
          this._threatHistory = this._threatHistory.slice(-this.historySize);
        }

        this.broadcastThreat(threatEntry);
      }
    }
  }

  /**
   * Broadcast a threat event to all connected WebSocket clients.
   * @param {Object} threat
   */
  broadcastThreat(threat) {
    const message = JSON.stringify({ type: 'threat', data: threat });
    this._broadcast(message);
  }

  /**
   * Broadcast stats snapshot to all connected WebSocket clients.
   * @param {Object} [stats]
   */
  broadcastStats(stats) {
    const payload = stats || this._buildStatsPayload();
    const message = JSON.stringify({ type: 'stats', data: payload });
    this._broadcast(message);
  }

  /**
   * Get count of connected WebSocket clients.
   * @returns {number}
   */
  getConnectedClients() {
    return this._clients.size;
  }

  /**
   * Handle WebSocket upgrade request.
   * @param {http.IncomingMessage} req
   * @param {net.Socket} socket
   */
  _handleUpgrade(req, socket) {
    if (req.url !== '/ws') {
      socket.end('HTTP/1.1 404 Not Found\r\n\r\n');
      return;
    }

    if (this._clients.size >= this.maxClients) {
      socket.end('HTTP/1.1 503 Service Unavailable\r\n\r\n');
      return;
    }

    const key = req.headers['sec-websocket-key'];
    if (!key) {
      socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
      return;
    }

    const acceptKey = this._computeAcceptKey(key);

    const headers = [
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Accept: ${acceptKey}`,
      '',
      ''
    ].join('\r\n');

    socket.write(headers);

    const client = { socket, alive: true };
    this._clients.add(client);

    // Send initial state
    const initMessage = JSON.stringify({
      type: 'init',
      data: {
        stats: this._buildStatsPayload(),
        recentThreats: this._threatHistory.slice(-50)
      }
    });
    this._sendToClient(client, initMessage);

    // Buffer for fragmented frames
    let frameBuffer = Buffer.alloc(0);

    socket.on('data', (data) => {
      frameBuffer = Buffer.concat([frameBuffer, data]);

      while (frameBuffer.length >= 2) {
        const decoded = this._decodeFrame(frameBuffer);
        if (!decoded) break;

        frameBuffer = frameBuffer.slice(decoded.bytesConsumed);

        if (decoded.opcode === 0x08) {
          // Close frame
          this._clients.delete(client);
          socket.end();
          return;
        }

        if (decoded.opcode === 0x09) {
          // Ping — respond with pong
          const pong = this._encodeFrame(decoded.payload, 0x0A);
          socket.write(pong);
          continue;
        }

        if (decoded.opcode === 0x0A) {
          // Pong
          client.alive = true;
          continue;
        }

        // Text frame (0x01) — handle commands
        if (decoded.opcode === 0x01) {
          try {
            const msg = JSON.parse(decoded.payload.toString('utf8'));
            this._handleClientMessage(client, msg);
          } catch (_) {
            // ignore malformed
          }
        }
      }
    });

    socket.on('close', () => {
      this._clients.delete(client);
    });

    socket.on('error', () => {
      this._clients.delete(client);
    });
  }

  /**
   * Compute Sec-WebSocket-Accept header value per RFC 6455.
   * @param {string} key — client's Sec-WebSocket-Key
   * @returns {string}
   */
  _computeAcceptKey(key) {
    return crypto.createHash('sha1')
      .update(key + WS_MAGIC_STRING)
      .digest('base64');
  }

  /**
   * Encode data into a WebSocket frame per RFC 6455.
   * Server-to-client frames are NOT masked.
   * @param {string|Buffer} data
   * @param {number} [opcode=0x01] — 0x01 text, 0x02 binary, 0x08 close, 0x09 ping, 0x0A pong
   * @returns {Buffer}
   */
  _encodeFrame(data, opcode = 0x01) {
    const payload = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
    const len = payload.length;

    let header;
    if (len < 126) {
      header = Buffer.alloc(2);
      header[0] = 0x80 | opcode; // FIN + opcode
      header[1] = len;
    } else if (len < 65536) {
      header = Buffer.alloc(4);
      header[0] = 0x80 | opcode;
      header[1] = 126;
      header.writeUInt16BE(len, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x80 | opcode;
      header[1] = 127;
      // Write 64-bit length (we only use lower 32 bits for practical sizes)
      header.writeUInt32BE(0, 2);
      header.writeUInt32BE(len, 6);
    }

    return Buffer.concat([header, payload]);
  }

  /**
   * Decode a WebSocket frame from a buffer per RFC 6455.
   * Client-to-server frames are masked.
   * @param {Buffer} buffer
   * @returns {Object|null} — {opcode, payload, bytesConsumed} or null if insufficient data
   */
  _decodeFrame(buffer) {
    if (buffer.length < 2) return null;

    const firstByte = buffer[0];
    const secondByte = buffer[1];

    const opcode = firstByte & 0x0F;
    const masked = (secondByte & 0x80) !== 0;
    let payloadLen = secondByte & 0x7F;
    let offset = 2;

    if (payloadLen === 126) {
      if (buffer.length < 4) return null;
      payloadLen = buffer.readUInt16BE(2);
      offset = 4;
    } else if (payloadLen === 127) {
      if (buffer.length < 10) return null;
      // Read lower 32 bits (upper 32 assumed zero for practical sizes)
      payloadLen = buffer.readUInt32BE(6);
      offset = 10;
    }

    let maskKey = null;
    if (masked) {
      if (buffer.length < offset + 4) return null;
      maskKey = buffer.slice(offset, offset + 4);
      offset += 4;
    }

    if (buffer.length < offset + payloadLen) return null;

    let payload = buffer.slice(offset, offset + payloadLen);

    if (masked && maskKey) {
      payload = Buffer.from(payload); // copy to avoid mutating original
      for (let i = 0; i < payload.length; i++) {
        payload[i] ^= maskKey[i % 4];
      }
    }

    return {
      opcode,
      payload,
      bytesConsumed: offset + payloadLen
    };
  }

  /**
   * Handle HTTP requests.
   */
  _handleHTTP(req, res) {
    const url = req.url.split('?')[0];

    if (req.method === 'GET' && url === '/') {
      this._serveDashboard(res);
    } else if (req.method === 'GET' && url === '/api/stats') {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify(this._buildStatsPayload()));
    } else if (req.method === 'GET' && url === '/api/threats') {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify(this._threatHistory.slice(-100)));
    } else if (req.method === 'POST' && url === '/api/ingest') {
      this._handleIngest(req, res);
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
    }
  }

  /**
   * Serve dashboard HTML.
   */
  _serveDashboard(res) {
    const htmlPath = path.join(__dirname, 'index.html');
    fs.readFile(htmlPath, 'utf8', (err, content) => {
      if (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Dashboard not found');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(content);
    });
  }

  /**
   * Handle POST /api/ingest for standalone scan ingestion.
   */
  _handleIngest(req, res) {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      try {
        const scanResult = JSON.parse(body);
        this.ingestScan(scanResult);
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
  }

  /**
   * Handle messages from WebSocket clients.
   */
  _handleClientMessage(client, msg) {
    if (msg.type === 'ping') {
      this._sendToClient(client, JSON.stringify({ type: 'pong' }));
    }
  }

  /**
   * Build statistics payload for API and WebSocket.
   */
  _buildStatsPayload() {
    const now = Date.now();
    const cutoff = now - 60000;
    const recentScans = this._scanTimestamps.filter(t => t >= cutoff);

    // Throughput: scans per second over last 60s
    const throughputPerSecond = [];
    for (let i = 59; i >= 0; i--) {
      const secStart = now - (i + 1) * 1000;
      const secEnd = i === 0 ? now + 1 : now - i * 1000;
      const count = recentScans.filter(t => t >= secStart && t < secEnd).length;
      throughputPerSecond.push(count);
    }

    // Avg latency
    const latencies = this._stats.latencyHistogram;
    const avgLatency = latencies.length > 0
      ? latencies.reduce((a, b) => a + b, 0) / latencies.length
      : 0;

    return {
      totalScans: this._stats.totalScans,
      totalThreats: this._stats.totalThreats,
      detectionRate: this._stats.totalScans > 0
        ? ((this._stats.totalThreats / this._stats.totalScans) * 100).toFixed(2)
        : '0.00',
      avgLatency: Math.round(avgLatency * 100) / 100,
      threatsByCategory: this._stats.threatsByCategory,
      threatsBySeverity: this._stats.threatsBySeverity,
      throughputPerSecond,
      connectedClients: this._clients.size,
      uptime: Math.floor((now - this._stats.startTime) / 1000)
    };
  }

  /**
   * Broadcast a message to all connected clients.
   */
  _broadcast(message) {
    const frame = this._encodeFrame(message);
    this._sendFrame(frame, this._clients);
  }

  /**
   * Send a message to a specific client.
   */
  _sendToClient(client, message) {
    const frame = this._encodeFrame(message);
    this._sendFrame(frame, [client]);
  }

  /**
   * Send a pre-encoded frame to a set of clients.
   */
  _sendFrame(frame, clients) {
    for (const client of clients) {
      try {
        client.socket.write(frame);
      } catch (_) {
        this._clients.delete(client);
      }
    }
  }

  /**
   * Start periodic stats broadcast (every 1 second).
   */
  _startStatsBroadcast() {
    this._statsInterval = setInterval(() => {
      if (this._clients.size > 0) {
        this.broadcastStats();
      }
    }, 1000);
  }
}

module.exports = { ThreatStreamServer };
