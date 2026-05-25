'use strict';

/**
 * Agent Shield — Open-Source Agent Integrations
 *
 * Plug-and-play wrappers for the open-source LLM and agent ecosystem:
 *
 *   Models / servers (all OpenAI-compatible endpoints):
 *     - Ollama          (local)
 *     - llama.cpp       (server mode)
 *     - vLLM            (high-throughput serving)
 *     - LocalAI         (drop-in OpenAI replacement)
 *     - LiteLLM         (universal LLM proxy)
 *     - OpenRouter      (gateway to any model)
 *     - Together AI / Fireworks / Groq (OpenAI-compatible)
 *
 *   Models with custom formats:
 *     - Hermes (Nous Research) — uses <tool_call>...</tool_call> XML tags;
 *       Shield parses tool calls out before execution and scans both the
 *       calling text AND the JSON arguments.
 *
 *   Agent frameworks:
 *     - AutoGen          (Microsoft, Python; conversable agents)
 *     - CrewAI           (Python; role-based crews)
 *     - smolagents       (HuggingFace; ReAct + CodeAgent)
 *     - Agno             (Python; agent + team framework)
 *     - OpenHands        (Devin-style autonomous coder)
 *     - mcp-agent        (any MCP host)
 *
 * Pattern: every wrapper returns a Shield-instrumented version of the
 * caller's existing client. Inputs are scanned BEFORE leaving the host;
 * outputs (including tool calls) are scanned BEFORE the host acts on them.
 * Tool descriptions are scanned at registration time (tool poisoning).
 *
 * Zero new dependencies. The caller's runtime stays as-is; we just wrap it.
 */

const { AgentShield } = require('./index');
const { ShieldAgent } = require('./shield-agent');
const { ShieldActions } = require('./shield-actions');

// =========================================================================
// Universal OpenAI-compatible wrapper
// =========================================================================

/**
 * Wrap any OpenAI-compatible chat-completions endpoint. Works for Ollama,
 * llama.cpp, vLLM, LocalAI, LiteLLM, OpenRouter, Together, Fireworks, Groq,
 * etc — anything that takes {messages, tools?} and returns choices[].
 *
 * @param {object} opts
 * @param {string} opts.baseUrl    — e.g. http://localhost:11434/v1 for Ollama
 * @param {string} [opts.apiKey]   — bearer; not required for local servers
 * @param {string} opts.model      — model id (llama3:8b, hermes-3, etc.)
 * @param {object} [opts.shield]   — AgentShield (or compatible) instance
 * @param {object} [opts.agent]    — ShieldAgent for triage
 * @param {object} [opts.actions]  — ShieldActions executor
 * @param {function} [opts.fetch]  — custom fetch (defaults to global fetch)
 * @returns {{chat: (args) => Promise<response>, stats}}
 */
function shieldOpenAICompatible(opts = {}) {
  if (!opts.baseUrl || typeof opts.baseUrl !== 'string') {
    throw new Error('shieldOpenAICompatible: baseUrl required');
  }
  if (!opts.model || typeof opts.model !== 'string') {
    throw new Error('shieldOpenAICompatible: model required');
  }
  const shield = opts.shield || new AgentShield();
  const agent = opts.agent || null;
  const actions = opts.actions || new ShieldActions();
  const fetchImpl = opts.fetch || globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    throw new Error('shieldOpenAICompatible: fetch is not available; pass opts.fetch or use Node 18+');
  }

  const stats = { calls: 0, blockedInputs: 0, blockedOutputs: 0, blockedTools: 0 };
  const url = opts.baseUrl.replace(/\/+$/, '') + '/chat/completions';

  return {
    stats,
    async chat({ messages, tools, ...rest } = {}) {
      if (!Array.isArray(messages)) throw new Error('chat: messages array required');
      stats.calls++;

      // 1. Pre-scan every user/system message + tool descriptions.
      for (const m of messages) {
        const content = stringifyContent(m.content);
        if (!content) continue;
        const verdict = agent
          ? await agent.investigate(content, { provenance: m.role === 'system' ? 'SYSTEM' : m.role === 'tool' ? 'TOOL_OUTPUT' : 'USER', source: 'openai-compat-input' })
          : null;
        const scan = verdict ? verdict.scan : shield.scan(content);
        if (verdictBlocked(verdict, scan)) {
          stats.blockedInputs++;
          return blockedResponse('input', verdict, scan, actions);
        }
      }
      if (Array.isArray(tools)) {
        for (const t of tools) {
          const desc = (t.function && t.function.description) || t.description || '';
          if (!desc) continue;
          const s = shield.scan(desc);
          if (severityIs(s, 'high') || severityIs(s, 'critical')) {
            stats.blockedTools++;
            return blockedResponse('tool-description', null, s, actions);
          }
        }
      }

      // 2. Call the upstream LLM.
      const headers = { 'content-type': 'application/json' };
      if (opts.apiKey) headers.authorization = `Bearer ${opts.apiKey}`;
      const resp = await fetchImpl(url, {
        method: 'POST',
        headers,
        body: JSON.stringify({ model: opts.model, messages, ...(tools ? { tools } : {}), ...rest }),
      });
      if (!resp.ok) {
        const body = await resp.text();
        throw new Error(`upstream ${resp.status}: ${body.slice(0, 400)}`);
      }
      const data = await resp.json();

      // 3. Post-scan every choice's content + tool calls.
      for (const choice of (data.choices || [])) {
        const msg = choice.message || {};
        const out = stringifyContent(msg.content);
        if (out) {
          const s = shield.scan(out);
          if (severityIs(s, 'critical')) {
            stats.blockedOutputs++;
            return blockedResponse('output', null, s, actions);
          }
        }
        for (const tc of (msg.tool_calls || [])) {
          const args = (tc.function && tc.function.arguments) || tc.arguments || '';
          if (typeof args !== 'string' || !args) continue;
          // Scan args raw + with implicit "fetch" verb + per-URL extraction
          // so bare-URL JSON arguments (SSRF, exfil endpoints) trigger the
          // verb-anchored rules that require whitespace before the URL.
          const s = mergedScan(mergedScan(shield.scan(args), shield.scan('fetch ' + args)), scanToolArgsForUrls(shield, args));
          if (severityIs(s, 'high') || severityIs(s, 'critical')) {
            stats.blockedTools++;
            return blockedResponse('tool-arguments', null, s, actions);
          }
        }
      }

      return data;
    },
  };
}

// =========================================================================
// Hermes-style XML tool-call wrapper (Nous Research models)
// =========================================================================

/**
 * Hermes models (Hermes-2-Pro, Hermes-3, etc.) emit tool calls as
 *   <tool_call>{"name": "...", "arguments": {...}}</tool_call>
 * tags inside the assistant message. This wrapper parses them, scans the
 * arguments JSON for injection, and only invokes the actual tool if Shield
 * approves. Use with any Hermes-compatible inference server (Ollama,
 * llama.cpp, vLLM, etc.) by passing the same baseUrl.
 *
 * Returns a `.chat()` that mirrors OpenAI shape but with parsed Hermes
 * tool_calls; and an `.executeToolCalls(toolCalls, registry)` helper that
 * scans each call before dispatching to the user's tool registry.
 */
function shieldHermes(opts = {}) {
  const base = shieldOpenAICompatible(opts);
  const shield = opts.shield || new AgentShield();
  const TOOL_CALL_RE = /<tool_call>([\s\S]*?)<\/tool_call>/g;

  function parseHermesToolCalls(text) {
    if (typeof text !== 'string') return { cleaned: '', toolCalls: [] };
    const toolCalls = [];
    const cleaned = text.replace(TOOL_CALL_RE, (_, inner) => {
      const trimmed = inner.trim();
      try {
        const parsed = JSON.parse(trimmed);
        if (parsed && typeof parsed.name === 'string') {
          toolCalls.push({
            id: `hermes-${toolCalls.length}-${Date.now()}`,
            type: 'function',
            function: {
              name: parsed.name,
              arguments: typeof parsed.arguments === 'string' ? parsed.arguments : JSON.stringify(parsed.arguments || {}),
            },
          });
        }
      } catch (_) { /* unparseable tool_call; drop silently */ }
      return '';
    }).trim();
    return { cleaned, toolCalls };
  }

  return {
    parseHermesToolCalls,
    stats: base.stats,

    async chat(args) {
      const result = await base.chat(args);
      // Augment OpenAI-shape with Hermes-parsed tool_calls per choice.
      for (const choice of (result.choices || [])) {
        const msg = choice.message || {};
        if (typeof msg.content === 'string' && msg.content.includes('<tool_call>')) {
          const { cleaned, toolCalls } = parseHermesToolCalls(msg.content);
          msg.content = cleaned;
          if (toolCalls.length) msg.tool_calls = (msg.tool_calls || []).concat(toolCalls);
        }
      }
      return result;
    },

    /**
     * Dispatch parsed Hermes tool calls through a user-supplied registry.
     * Each call's name + arguments are scanned for injection; suspicious
     * calls are skipped and reported.
     *
     * @param {Array} toolCalls — as produced by .chat() above
     * @param {Object<string, function>} registry — { tool_name: async (args) => result }
     * @returns {Promise<Array<{name, arguments, result?, error?, skipped?, threat?}>>}
     */
    async executeToolCalls(toolCalls, registry) {
      if (!Array.isArray(toolCalls)) throw new Error('executeToolCalls: toolCalls array required');
      if (!registry || typeof registry !== 'object') throw new Error('executeToolCalls: registry object required');
      const out = [];
      for (const tc of toolCalls) {
        const name = tc.function?.name;
        const argStr = tc.function?.arguments || '';
        // Scan tool name (lookalike attacks) + arguments (payload injection).
        const nameScan = shield.scan(name || '');
        const argScan = mergedScan(mergedScan(shield.scan(argStr), shield.scan('fetch ' + argStr)), scanToolArgsForUrls(shield, argStr));
        if (severityIs(nameScan, 'critical') || severityIs(argScan, 'critical') || severityIs(argScan, 'high')) {
          out.push({ name, arguments: argStr, skipped: true, threat: (argScan.threats[0] || nameScan.threats[0]) || null });
          continue;
        }
        if (!registry[name]) {
          out.push({ name, arguments: argStr, error: `unknown tool: ${name}` });
          continue;
        }
        let args;
        try { args = JSON.parse(argStr || '{}'); }
        catch (e) { out.push({ name, arguments: argStr, error: `bad JSON arguments: ${e.message}` }); continue; }
        try {
          const result = await registry[name](args);
          out.push({ name, arguments: argStr, result });
        } catch (err) {
          out.push({ name, arguments: argStr, error: err.message });
        }
      }
      return out;
    },
  };
}

// =========================================================================
// Generic Python-host bridge (AutoGen / CrewAI / smolagents / Agno)
// =========================================================================

/**
 * For Python agent frameworks running in a subprocess, you'd typically:
 *   1. Wrap their LLM client with shieldOpenAICompatible if it speaks the
 *      OpenAI Chat Completions API (most do, via litellm or direct).
 *   2. Use the message-bus pattern below for tool-call interception when
 *      the framework exposes a `before_tool_call` / `on_message` hook.
 *
 * `shieldMessageBus()` is a tiny event router the host calls into. It
 * returns scan verdicts that the host translates into framework-specific
 * action (e.g. AutoGen `reply()` with error, CrewAI `RaiseException`, etc.).
 */
function shieldMessageBus(opts = {}) {
  const shield = opts.shield || new AgentShield();
  const agent = opts.agent || null;
  return {
    /** Call BEFORE forwarding a message to the LLM. */
    async onInbound(msg, ctx = {}) {
      const text = stringifyContent(msg.content || msg.text || '');
      if (!text) return { allow: true };
      const verdict = agent
        ? await agent.investigate(text, { provenance: msg.role === 'system' ? 'SYSTEM' : msg.role === 'tool' ? 'TOOL_OUTPUT' : 'USER', source: ctx.source || 'bus-inbound' })
        : null;
      const scan = verdict ? verdict.scan : shield.scan(text);
      const blocked = verdictBlocked(verdict, scan);
      return {
        allow: !blocked,
        verdict,
        scan,
        rewrite: verdict && verdict.action === 'rewrite' ? verdict.rewritten : null,
        reason: verdict ? verdict.reason : blocked ? 'detector flagged' : null,
      };
    },

    /** Call BEFORE executing a tool the LLM asked for. */
    async onToolCall(name, args, ctx = {}) {
      const argStr = typeof args === 'string' ? args : JSON.stringify(args || {});
      const nameScan = shield.scan(name || '');
      // Scan args twice: raw (catches override/injection text) and with an
      // implicit "fetch" verb prepended so a bare URL value in JSON args
      // still triggers SSRF / data-exfiltration patterns that require a verb.
      const argScan = shield.scan(argStr);
      const fetchArgScan = shield.scan('fetch ' + argStr);
      const urlScan = scanToolArgsForUrls(shield, argStr);
      const worst = mergedScan(mergedScan(argScan, fetchArgScan), urlScan);
      const danger = severityIs(nameScan, 'critical') || severityIs(worst, 'critical') || severityIs(worst, 'high');
      return {
        allow: !danger,
        scan: worst,
        nameScan,
        reason: danger ? `tool ${name} blocked: ${(worst.threats[0] || nameScan.threats[0] || {}).category || 'high severity'}` : null,
        source: ctx.source || 'bus-tool',
      };
    },

    /** Call AFTER receiving LLM output, BEFORE returning to user. */
    async onOutbound(text, ctx = {}) {
      const t = stringifyContent(text);
      if (!t) return { allow: true };
      const scan = shield.scan(t);
      const blocked = severityIs(scan, 'critical');
      return { allow: !blocked, scan, reason: blocked ? 'output flagged critical' : null, source: ctx.source || 'bus-outbound' };
    },
  };
}

// =========================================================================
// Convenience presets
// =========================================================================

const presets = Object.freeze({
  ollama: (opts) => shieldOpenAICompatible({ baseUrl: 'http://localhost:11434/v1', model: 'llama3', ...opts }),
  llamacpp: (opts) => shieldOpenAICompatible({ baseUrl: 'http://localhost:8080/v1', model: 'local', ...opts }),
  vllm: (opts) => shieldOpenAICompatible({ baseUrl: 'http://localhost:8000/v1', model: 'local', ...opts }),
  localai: (opts) => shieldOpenAICompatible({ baseUrl: 'http://localhost:8080/v1', model: 'local', ...opts }),
  litellm: (opts) => shieldOpenAICompatible({ baseUrl: 'http://localhost:4000/v1', model: 'gpt-3.5-turbo', ...opts }),
  openrouter: (opts) => shieldOpenAICompatible({ baseUrl: 'https://openrouter.ai/api/v1', model: 'openai/gpt-3.5-turbo', ...opts }),
  together: (opts) => shieldOpenAICompatible({ baseUrl: 'https://api.together.xyz/v1', model: 'meta-llama/Llama-3-8b-chat-hf', ...opts }),
  groq: (opts) => shieldOpenAICompatible({ baseUrl: 'https://api.groq.com/openai/v1', model: 'llama-3.1-8b-instant', ...opts }),
  fireworks: (opts) => shieldOpenAICompatible({ baseUrl: 'https://api.fireworks.ai/inference/v1', model: 'accounts/fireworks/models/llama-v3-8b-instruct', ...opts }),
  hermes: (opts) => shieldHermes({ baseUrl: opts && opts.baseUrl || 'http://localhost:11434/v1', model: opts && opts.model || 'hermes-3', ...opts }),
});

// =========================================================================
// Helpers
// =========================================================================

function stringifyContent(c) {
  if (typeof c === 'string') return c;
  if (Array.isArray(c)) return c.map((part) => (typeof part === 'string' ? part : (part && part.text) || '')).join(' ');
  if (c && typeof c === 'object') return c.text || JSON.stringify(c);
  return '';
}

function severityIs(scan, sev) {
  return scan && scan.stats && !!scan.stats[sev];
}

function mergedScan(a, b) {
  // Combine two scan results into one whose threats and stats are the union.
  if (!a) return b;
  if (!b) return a;
  const threats = (a.threats || []).concat(b.threats || []);
  const stats = { critical: 0, high: 0, medium: 0, low: 0, scanTimeMs: 0 };
  for (const k of Object.keys(stats)) stats[k] = (a.stats?.[k] || 0) + (b.stats?.[k] || 0);
  return { status: stats.critical ? 'danger' : stats.high ? 'warning' : stats.medium ? 'caution' : 'safe', threats, stats };
}

/**
 * Pull every URL-shaped substring out of a tool-arguments string (which is
 * usually JSON) and re-scan each one with an implicit "fetch " verb. Without
 * this, a bare-URL value like `{"url":"http://169.254.169.254/..."}` fails
 * the SSRF rule because the verb→URL rules require whitespace before the URL.
 */
const URL_IN_ARG_RE = /https?:\/\/[^\s"',<>)}\]]+/g;
function scanToolArgsForUrls(shield, argStr) {
  if (typeof argStr !== 'string' || !argStr) return null;
  let merged = null;
  let m;
  URL_IN_ARG_RE.lastIndex = 0;
  while ((m = URL_IN_ARG_RE.exec(argStr)) !== null) {
    const sub = shield.scan('fetch ' + m[0]);
    merged = merged ? mergedScan(merged, sub) : sub;
  }
  return merged;
}

function verdictBlocked(verdict, scan) {
  if (verdict && (verdict.action === 'block' || verdict.action === 'escalate' || verdict.action === 'quarantine')) return true;
  if (severityIs(scan, 'critical')) return true;
  return false;
}

function blockedResponse(phase, verdict, scan, actions) {
  const reason = verdict ? verdict.reason : `phase=${phase}: ${(scan.threats[0] || {}).category || 'critical severity'}`;
  return {
    id: `shield-block-${Date.now()}`,
    object: 'chat.completion',
    blocked: true,
    blockedPhase: phase,
    blockedReason: reason,
    choices: [
      {
        index: 0,
        finish_reason: 'content_filter',
        message: { role: 'assistant', content: actions ? actions.blockedResponse : 'This request was blocked by Agent Shield for safety reasons.' },
      },
    ],
  };
}

module.exports = {
  shieldOpenAICompatible,
  shieldHermes,
  shieldMessageBus,
  presets,
  // exposed for tests:
  parseHermesToolCallsForTest: (text) => {
    const TOOL_CALL_RE = /<tool_call>([\s\S]*?)<\/tool_call>/g;
    const out = [];
    text.replace(TOOL_CALL_RE, (_, inner) => {
      try { out.push(JSON.parse(inner.trim())); } catch (_) { /* skip */ }
      return '';
    });
    return out;
  },
};
