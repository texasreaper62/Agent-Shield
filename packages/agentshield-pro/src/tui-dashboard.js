'use strict';

// Terminal UI Dashboard for Agent Shield Pro
// Zero external dependencies — uses only readline, process.stdout, and ANSI escape codes

const readline = require('readline');

// ── ANSI escape helpers ───────────────────────────────────────────────

const ESC = '\x1b[';
const ANSI = {
  reset: `${ESC}0m`,
  bold: `${ESC}1m`,
  dim: `${ESC}2m`,
  // Foreground colors
  red: `${ESC}31m`,
  green: `${ESC}32m`,
  yellow: `${ESC}33m`,
  blue: `${ESC}34m`,
  magenta: `${ESC}35m`,
  cyan: `${ESC}36m`,
  white: `${ESC}37m`,
  gray: `${ESC}90m`,
  // Background colors
  bgRed: `${ESC}41m`,
  bgGreen: `${ESC}42m`,
  bgYellow: `${ESC}43m`,
  bgCyan: `${ESC}46m`,
  // Cursor / screen
  clearScreen: `${ESC}2J`,
  cursorHome: `${ESC}H`,
  hideCursor: `${ESC}?25l`,
  showCursor: `${ESC}?25h`,
  saveCursor: `${ESC}s`,
  restoreCursor: `${ESC}u`
};

/**
 * Moves cursor to a given row and column (1-based).
 * @param {number} row
 * @param {number} col
 * @returns {string} ANSI escape sequence
 */
function moveTo(row, col) {
  return `${ESC}${row};${col}H`;
}

/**
 * Strips ANSI escape sequences from a string for length calculation.
 * @param {string} str
 * @returns {string}
 */
function stripAnsi(str) {
  return str.replace(/\x1b\[[0-9;]*m/g, '');
}

/**
 * Pads or truncates a string to exactly `width` visible characters.
 * @param {string} str - Input (may contain ANSI codes)
 * @param {number} width - Target visible width
 * @returns {string}
 */
function fitWidth(str, width) {
  const visible = stripAnsi(str);
  if (visible.length > width) {
    return str.substring(0, str.length - (visible.length - width));
  }
  return str + ' '.repeat(width - visible.length);
}

// ── Box-drawing constants ────────────────────────────────────────────

const BOX = {
  topLeft: '\u250c', topRight: '\u2510',
  botLeft: '\u2514', botRight: '\u2518',
  horiz: '\u2500', vert: '\u2502',
  teeRight: '\u251c', teeLeft: '\u2524',
  teeDown: '\u252c', teeUp: '\u2534',
  cross: '\u253c'
};

// ── Severity helpers ─────────────────────────────────────────────────

const SEVERITY_COLORS = {
  critical: ANSI.red,
  crit: ANSI.red,
  high: ANSI.red,
  warning: ANSI.yellow,
  warn: ANSI.yellow,
  medium: ANSI.yellow,
  low: ANSI.cyan,
  info: ANSI.cyan,
  safe: ANSI.green
};

/**
 * Colorizes a severity tag.
 * @param {string} severity
 * @returns {string}
 */
function colorSeverity(severity) {
  const key = (severity || 'info').toLowerCase();
  const color = SEVERITY_COLORS[key] || ANSI.white;
  return `${color}${ANSI.bold}[${severity.toUpperCase()}]${ANSI.reset}`;
}

/**
 * Formats a number with comma separators.
 * @param {number} n
 * @returns {string}
 */
function formatNum(n) {
  if (n == null) return '0';
  return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/**
 * Formats milliseconds into a human-readable uptime string.
 * @param {number} ms
 * @returns {string}
 */
function formatUptime(ms) {
  const seconds = Math.floor(ms / 1000);
  const m = Math.floor(seconds / 60);
  const h = Math.floor(m / 60);
  const d = Math.floor(h / 24);
  if (d > 0) return `${d}d ${h % 24}h ${m % 60}m`;
  if (h > 0) return `${h}h ${m % 60}m`;
  if (m > 0) return `${m}m ${seconds % 60}s`;
  return `${seconds}s`;
}

// ── Dashboard class ──────────────────────────────────────────────────

const DEFAULT_WIDTH = 60;
const MAX_ALERTS = 6;
const MAX_AGENTS = 5;

/**
 * Interactive terminal dashboard for monitoring Agent Shield security in real-time.
 * Uses only Node.js built-in modules: readline, process.stdout, tty.
 */
class TUIDashboard {
  /**
   * @param {Object} [options={}]
   * @param {number} [options.refreshInterval=1000] - Refresh interval in milliseconds
   * @param {string} [options.licenseType='Pro'] - License tier label
   * @param {string} [options.org=''] - Organization name
   * @param {string} [options.expires=''] - License expiration date
   * @param {number} [options.width=60] - Dashboard width in characters
   */
  constructor(options) {
    const opts = options || {};
    this.refreshInterval = opts.refreshInterval || 1000;
    this.licenseType = opts.licenseType || 'Pro';
    this.org = opts.org || '';
    this.expires = opts.expires || '';
    this.width = opts.width || DEFAULT_WIDTH;

    this._running = false;
    this._timer = null;
    this._rl = null;
    this._startTime = null;
    this._currentView = 'main';

    // State
    this._stats = {
      scans: 0,
      threats: 0,
      blocked: 0,
      warnings: 0,
      fpRate: 0,
      uptimeMs: 0
    };
    this._alerts = [];
    this._agents = [];
    this._events = [];
  }

  /**
   * Starts the dashboard, clears the screen, begins rendering loop.
   */
  start() {
    if (this._running) return;
    this._running = true;
    this._startTime = Date.now();

    // Hide cursor and clear
    process.stdout.write(ANSI.hideCursor);
    process.stdout.write(ANSI.clearScreen);
    process.stdout.write(ANSI.cursorHome);

    // Set up keyboard input
    if (process.stdin.isTTY) {
      readline.emitKeypressEvents(process.stdin);
      process.stdin.setRawMode(true);
      process.stdin.resume();
    }

    this._rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: false
    });

    this._keypressHandler = (str, key) => {
      if (!key) return;
      this._handleKey(key);
    };
    process.stdin.on('keypress', this._keypressHandler);

    console.log('[Agent Shield Pro] Dashboard started');

    // Render loop
    this._render();
    this._timer = setInterval(() => {
      if (this._running) {
        this._stats.uptimeMs = Date.now() - this._startTime;
        this._render();
      }
    }, this.refreshInterval);
  }

  /**
   * Stops the dashboard and restores the terminal.
   */
  stop() {
    if (!this._running) return;
    this._running = false;

    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }

    if (process.stdin.isTTY) {
      process.stdin.removeListener('keypress', this._keypressHandler);
      try { process.stdin.setRawMode(false); } catch (_) { /* ignore */ }
    }

    if (this._rl) {
      this._rl.close();
      this._rl = null;
    }

    // Restore terminal
    process.stdout.write(ANSI.showCursor);
    process.stdout.write(ANSI.clearScreen);
    process.stdout.write(ANSI.cursorHome);

    console.log('[Agent Shield Pro] Dashboard stopped');
  }

  /**
   * Updates the displayed statistics.
   * @param {Object} stats - Partial stats object to merge
   * @param {number} [stats.scans] - Total scan count
   * @param {number} [stats.threats] - Threat count
   * @param {number} [stats.blocked] - Blocked count
   * @param {number} [stats.warnings] - Warning count
   * @param {number} [stats.fpRate] - False positive rate (0-100)
   */
  updateStats(stats) {
    if (!stats) return;
    Object.assign(this._stats, stats);
  }

  /**
   * Adds an alert to the alerts feed. Keeps the most recent alerts only.
   * @param {Object} alert
   * @param {string} alert.severity - 'critical' | 'high' | 'warn' | 'info'
   * @param {string} alert.message - Alert description
   * @param {string} [alert.timestamp] - ISO timestamp (auto-set if omitted)
   */
  addAlert(alert) {
    if (!alert) return;
    if (!alert.timestamp) {
      alert.timestamp = new Date().toISOString();
    }
    this._alerts.unshift(alert);
    if (this._alerts.length > MAX_ALERTS * 2) {
      this._alerts = this._alerts.slice(0, MAX_ALERTS * 2);
    }
  }

  /**
   * Adds an event to the activity log. Can be an agent status update.
   * @param {Object} event
   * @param {string} event.type - Event type ('agent-status', 'scan', 'config-change', etc.)
   * @param {string} [event.agentId] - Agent identifier
   * @param {string} [event.status] - 'online' | 'idle' | 'offline'
   * @param {number} [event.scans] - Agent scan count
   * @param {number} [event.threats] - Agent threat count
   * @param {string} [event.message] - Event description
   */
  addEvent(event) {
    if (!event) return;
    if (!event.timestamp) {
      event.timestamp = new Date().toISOString();
    }

    // Track agent status
    if (event.type === 'agent-status' && event.agentId) {
      const existing = this._agents.findIndex(a => a.agentId === event.agentId);
      const agentEntry = {
        agentId: event.agentId,
        status: event.status || 'online',
        scans: event.scans || 0,
        threats: event.threats || 0,
        lastSeen: event.timestamp
      };
      if (existing >= 0) {
        this._agents[existing] = agentEntry;
      } else {
        this._agents.push(agentEntry);
        if (this._agents.length > MAX_AGENTS * 2) {
          this._agents = this._agents.slice(0, MAX_AGENTS * 2);
        }
      }
    }

    this._events.unshift(event);
    if (this._events.length > 50) {
      this._events = this._events.slice(0, 50);
    }
  }

  // ── Private: keyboard handling ──────────────────────────────────

  /**
   * @param {Object} key - Keypress key object
   * @private
   */
  _handleKey(key) {
    if (key.name === 'q' || (key.ctrl && key.name === 'c')) {
      this.stop();
      process.exit(0);
    } else if (key.name === 'r') {
      this._render();
    } else if (key.name === 'a') {
      this._currentView = this._currentView === 'alerts' ? 'main' : 'alerts';
      this._render();
    } else if (key.name === 's') {
      this._currentView = this._currentView === 'stats' ? 'main' : 'stats';
      this._render();
    } else if (key.name === 'h') {
      this._currentView = this._currentView === 'help' ? 'main' : 'help';
      this._render();
    }
  }

  // ── Private: rendering ──────────────────────────────────────────

  /**
   * Renders the full dashboard to stdout.
   * @private
   */
  _render() {
    const w = this.width;
    const inner = w - 2; // content width inside the box
    const lines = [];

    // ── Title bar ──
    const title = ' Agent Shield Pro Dashboard ';
    const padLen = inner - title.length;
    const leftPad = Math.floor(padLen / 2);
    const rightPad = padLen - leftPad;
    lines.push(
      `${ANSI.cyan}${BOX.topLeft}${BOX.horiz.repeat(leftPad)}${ANSI.bold}${ANSI.white}${title}${ANSI.reset}${ANSI.cyan}${BOX.horiz.repeat(rightPad)}${BOX.topRight}${ANSI.reset}`
    );

    // ── License row ──
    const licenseInfo = ` License: ${this.licenseType}` +
      (this.org ? ` | Org: ${this.org}` : '') +
      (this.expires ? ` | Expires: ${this.expires}` : '');
    lines.push(this._row(licenseInfo, inner));

    // ── Stats divider (three columns) ──
    const col1w = Math.floor(inner / 3);
    const col2w = Math.floor(inner / 3);
    const col3w = inner - col1w - col2w - 2; // -2 for internal separators
    lines.push(
      `${ANSI.cyan}${BOX.teeRight}${BOX.horiz.repeat(col1w)}${BOX.teeDown}${BOX.horiz.repeat(col2w)}${BOX.teeDown}${BOX.horiz.repeat(col3w)}${BOX.teeLeft}${ANSI.reset}`
    );

    // Stats row 1
    const s1c1 = ` Scans: ${ANSI.bold}${ANSI.white}${formatNum(this._stats.scans)}${ANSI.reset}`;
    const s1c2 = ` Threats: ${ANSI.bold}${ANSI.red}${formatNum(this._stats.threats)}${ANSI.reset}`;
    const s1c3 = ` FP Rate: ${ANSI.bold}${ANSI.green}${this._stats.fpRate}%${ANSI.reset}`;
    lines.push(this._threeColRow(s1c1, s1c2, s1c3, col1w, col2w, col3w));

    // Stats row 2
    const s2c1 = ` Blocked: ${ANSI.bold}${ANSI.yellow}${formatNum(this._stats.blocked)}${ANSI.reset}`;
    const s2c2 = ` Warnings: ${ANSI.bold}${ANSI.yellow}${formatNum(this._stats.warnings)}${ANSI.reset}`;
    const uptimeMs = this._stats.uptimeMs || (this._startTime ? Date.now() - this._startTime : 0);
    const s2c3 = ` Uptime: ${ANSI.bold}${ANSI.cyan}${formatUptime(uptimeMs)}${ANSI.reset}`;
    lines.push(this._threeColRow(s2c1, s2c2, s2c3, col1w, col2w, col3w));

    // ── Alerts section ──
    lines.push(
      `${ANSI.cyan}${BOX.teeRight}${BOX.horiz.repeat(col1w)}${BOX.teeUp}${BOX.horiz.repeat(col2w)}${BOX.teeUp}${BOX.horiz.repeat(col3w)}${BOX.teeLeft}${ANSI.reset}`
    );
    lines.push(this._row(` ${ANSI.bold}${ANSI.white}Recent Alerts${ANSI.reset}`, inner));

    const alertsToShow = this._alerts.slice(0, MAX_ALERTS);
    if (alertsToShow.length === 0) {
      lines.push(this._row(` ${ANSI.dim}No alerts${ANSI.reset}`, inner));
    } else {
      for (const alert of alertsToShow) {
        const sev = colorSeverity(alert.severity || 'info');
        const msg = ` ${sev} ${alert.message || ''}`;
        lines.push(this._row(msg, inner));
      }
    }

    // ── Agent Status section ──
    lines.push(this._divider(inner));
    lines.push(this._row(` ${ANSI.bold}${ANSI.white}Agent Status${ANSI.reset}`, inner));

    const agentsToShow = this._agents.slice(0, MAX_AGENTS);
    if (agentsToShow.length === 0) {
      lines.push(this._row(` ${ANSI.dim}No agents registered${ANSI.reset}`, inner));
    } else {
      for (const agent of agentsToShow) {
        const statusIcon = agent.status === 'online'
          ? `${ANSI.green}\u25cf${ANSI.reset}`
          : agent.status === 'idle'
            ? `${ANSI.gray}\u25cb${ANSI.reset}`
            : `${ANSI.red}\u25cf${ANSI.reset}`;
        const statusLabel = (agent.status || 'unknown').charAt(0).toUpperCase() + (agent.status || 'unknown').slice(1);
        const agentLine = ` ${fitWidth(agent.agentId, 15)} ${statusIcon} ${fitWidth(statusLabel, 8)} Scans: ${fitWidth(formatNum(agent.scans), 6)} Threats: ${agent.threats}`;
        lines.push(this._row(agentLine, inner));
      }
    }

    // ── Help / footer ──
    lines.push(this._divider(inner));
    const footer = ` ${ANSI.dim}[q]${ANSI.reset} Quit ${ANSI.dim}[r]${ANSI.reset} Refresh ${ANSI.dim}[a]${ANSI.reset} Alerts ${ANSI.dim}[s]${ANSI.reset} Stats ${ANSI.dim}[h]${ANSI.reset} Help`;
    lines.push(this._row(footer, inner));
    lines.push(
      `${ANSI.cyan}${BOX.botLeft}${BOX.horiz.repeat(inner)}${BOX.botRight}${ANSI.reset}`
    );

    // Write to stdout in one shot
    const output = ANSI.cursorHome + lines.join('\n') + '\n';
    process.stdout.write(output);
  }

  /**
   * Creates a bordered row with content fitted to the inner width.
   * @param {string} content - Row content (may contain ANSI)
   * @param {number} innerWidth - Available content width
   * @returns {string}
   * @private
   */
  _row(content, innerWidth) {
    const visible = stripAnsi(content);
    const pad = innerWidth - visible.length;
    const padding = pad > 0 ? ' '.repeat(pad) : '';
    return `${ANSI.cyan}${BOX.vert}${ANSI.reset}${content}${padding}${ANSI.cyan}${BOX.vert}${ANSI.reset}`;
  }

  /**
   * Creates a three-column row with separators.
   * @param {string} c1 - Column 1 content
   * @param {string} c2 - Column 2 content
   * @param {string} c3 - Column 3 content
   * @param {number} w1 - Column 1 width
   * @param {number} w2 - Column 2 width
   * @param {number} w3 - Column 3 width
   * @returns {string}
   * @private
   */
  _threeColRow(c1, c2, c3, w1, w2, w3) {
    const v1 = stripAnsi(c1);
    const v2 = stripAnsi(c2);
    const v3 = stripAnsi(c3);
    const p1 = w1 - v1.length;
    const p2 = w2 - v2.length;
    const p3 = w3 - v3.length;
    return (
      `${ANSI.cyan}${BOX.vert}${ANSI.reset}` +
      c1 + (p1 > 0 ? ' '.repeat(p1) : '') +
      `${ANSI.cyan}${BOX.vert}${ANSI.reset}` +
      c2 + (p2 > 0 ? ' '.repeat(p2) : '') +
      `${ANSI.cyan}${BOX.vert}${ANSI.reset}` +
      c3 + (p3 > 0 ? ' '.repeat(p3) : '') +
      `${ANSI.cyan}${BOX.vert}${ANSI.reset}`
    );
  }

  /**
   * Creates a horizontal divider row.
   * @param {number} innerWidth
   * @returns {string}
   * @private
   */
  _divider(innerWidth) {
    return `${ANSI.cyan}${BOX.teeRight}${BOX.horiz.repeat(innerWidth)}${BOX.teeLeft}${ANSI.reset}`;
  }
}

// ── Convenience launcher ─────────────────────────────────────────────

/**
 * Convenience function to launch a TUI dashboard.
 * Creates a dashboard instance, optionally connects to a shield,
 * handles SIGINT for graceful shutdown, and starts rendering.
 *
 * @param {Object} [options={}]
 * @param {number} [options.refreshInterval=1000] - Refresh interval in ms
 * @param {string} [options.licenseType='Pro'] - License label
 * @param {string} [options.org=''] - Organization name
 * @param {string} [options.expires=''] - Expiration date string
 * @param {number} [options.width=60] - Dashboard width
 * @param {Object} [options.shield=null] - AgentShield instance to monitor
 * @returns {TUIDashboard} The running dashboard instance
 */
function launchDashboard(options) {
  const opts = options || {};
  const dashboard = new TUIDashboard(opts);

  // Graceful shutdown on SIGINT
  const sigintHandler = () => {
    console.log('\n[Agent Shield Pro] Shutting down dashboard...');
    dashboard.stop();
    process.removeListener('SIGINT', sigintHandler);
    process.exit(0);
  };
  process.on('SIGINT', sigintHandler);

  // If a shield instance is provided, wire up event forwarding
  if (opts.shield) {
    const shield = opts.shield;

    // Poll stats if the shield exposes getStats()
    if (typeof shield.getStats === 'function') {
      const pollStats = () => {
        if (!dashboard._running) return;
        try {
          const stats = shield.getStats();
          dashboard.updateStats(stats);
        } catch (_) { /* ignore */ }
      };
      setInterval(pollStats, opts.refreshInterval || 1000);
      pollStats();
    }

    // Listen for threat events if the shield is an EventEmitter
    if (typeof shield.on === 'function') {
      shield.on('threat', (event) => {
        dashboard.addAlert({
          severity: event.severity || 'warn',
          message: event.message || `Threat detected: ${event.type || 'unknown'}`
        });
      });

      shield.on('scan', (event) => {
        dashboard.updateStats({ scans: (dashboard._stats.scans || 0) + 1 });
      });

      shield.on('block', (event) => {
        dashboard.addAlert({
          severity: 'critical',
          message: event.message || 'Request blocked'
        });
      });
    }
  }

  dashboard.start();
  console.log('[Agent Shield Pro] Dashboard launched — press q to quit');
  return dashboard;
}

module.exports = {
  TUIDashboard,
  launchDashboard,
  // Expose helpers for testing
  ANSI,
  formatNum,
  formatUptime,
  stripAnsi
};
