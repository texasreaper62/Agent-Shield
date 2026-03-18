'use strict';

/**
 * Agent Shield — Framework Integrations
 *
 * Plug-and-play integrations for popular AI frameworks:
 * - LangChain
 * - Anthropic SDK (Claude)
 * - OpenAI SDK
 * - Vercel AI SDK
 * - Generic fetch wrapper
 */

const { AgentShield } = require('./index');
const { PIIRedactor } = require('./pii');
const { CircuitBreaker } = require('./circuit-breaker');

// =========================================================================
// LangChain Integration
// =========================================================================

/**
 * LangChain callback handler that scans inputs/outputs for threats.
 *
 * Usage:
 *   const { ShieldCallbackHandler } = require('agent-shield/src/integrations');
 *   const handler = new ShieldCallbackHandler({ blockOnThreat: true });
 *   const chain = new LLMChain({ llm, prompt, callbacks: [handler] });
 */
class ShieldCallbackHandler {
  constructor(options = {}) {
    this.shield = new AgentShield({
      sensitivity: options.sensitivity || 'high',
      blockOnThreat: options.blockOnThreat || false
    });
    this.piiRedactor = options.pii ? new PIIRedactor() : null;
    this.onThreat = options.onThreat || null;
    this.name = 'AgentShieldCallback';
  }

  async handleLLMStart(_llm, prompts) {
    for (const prompt of prompts) {
      const result = this.shield.scanInput(prompt);
      if (result.threats.length > 0 && this.onThreat) {
        this.onThreat({ phase: 'input', threats: result.threats, text: prompt });
      }
      if (result.blocked) {
        throw new ShieldBlockError('Input blocked by Agent Shield', result.threats);
      }
    }
  }

  async handleLLMEnd(output) {
    const text = output?.generations?.[0]?.[0]?.text || '';
    if (!text) return;

    const result = this.shield.scanOutput(text);
    if (result.threats.length > 0 && this.onThreat) {
      this.onThreat({ phase: 'output', threats: result.threats, text });
    }
    if (result.blocked) {
      throw new ShieldBlockError('Output blocked by Agent Shield', result.threats);
    }
  }

  async handleChainStart(_chain, inputs) {
    const text = typeof inputs === 'string' ? inputs : JSON.stringify(inputs);
    const result = this.shield.scanInput(text);
    if (result.blocked) {
      throw new ShieldBlockError('Chain input blocked by Agent Shield', result.threats);
    }
  }

  async handleToolStart(_tool, input) {
    const result = this.shield.scanInput(input);
    if (result.blocked) {
      throw new ShieldBlockError('Tool input blocked by Agent Shield', result.threats);
    }
  }

  getStats() {
    return this.shield.getStats();
  }
}

// =========================================================================
// Anthropic SDK Integration
// =========================================================================

/**
 * Wraps an Anthropic client with threat scanning on messages.
 *
 * Usage:
 *   const Anthropic = require('@anthropic-ai/sdk');
 *   const { shieldAnthropicClient } = require('agent-shield/src/integrations');
 *   const client = shieldAnthropicClient(new Anthropic(), { blockOnThreat: true });
 *   const msg = await client.messages.create({ model: 'claude-sonnet-4-20250514', messages: [...] });
 */
function shieldAnthropicClient(client, options = {}) {
  const shield = new AgentShield({
    sensitivity: options.sensitivity || 'high',
    blockOnThreat: options.blockOnThreat || false
  });
  const piiRedactor = options.pii ? new PIIRedactor() : null;
  const breaker = options.circuitBreaker ? new CircuitBreaker(options.circuitBreaker) : null;
  const onThreat = options.onThreat || null;

  const originalCreate = client.messages.create.bind(client.messages);

  client.messages.create = async function shieldedCreate(params) {
    // Circuit breaker check
    if (breaker) {
      const status = breaker.check();
      if (!status.allowed) {
        throw new ShieldBlockError(`Circuit breaker open: ${status.reason}`, []);
      }
    }

    // Scan all message content
    for (const msg of params.messages || []) {
      const text = extractAnthropicText(msg);
      if (!text) continue;

      // PII redaction
      if (piiRedactor && msg.role === 'user') {
        const piiResult = piiRedactor.redact(text);
        if (piiResult.count > 0) {
          setAnthropicText(msg, piiResult.redacted);
        }
      }

      const result = shield.scanInput(text);
      if (result.threats.length > 0) {
        if (onThreat) onThreat({ phase: 'input', role: msg.role, threats: result.threats });
        if (breaker) breaker.recordThreat(result.threats.length);
        if (result.blocked) {
          throw new ShieldBlockError('Message blocked by Agent Shield', result.threats);
        }
      }
    }

    // Scan system prompt
    if (params.system) {
      const sysText = typeof params.system === 'string' ? params.system : params.system.map(b => b.text || '').join(' ');
      const sysResult = shield.scanInput(sysText);
      if (sysResult.blocked) {
        throw new ShieldBlockError('System prompt contains threats', sysResult.threats);
      }
    }

    // Make the actual API call
    const response = await originalCreate(params);

    // Scan output
    const outputText = response.content?.map(b => b.text || '').join(' ') || '';
    if (outputText) {
      const outputResult = shield.scanOutput(outputText);
      if (outputResult.threats.length > 0 && onThreat) {
        onThreat({ phase: 'output', threats: outputResult.threats });
      }
      if (outputResult.blocked) {
        throw new ShieldBlockError('Response blocked by Agent Shield', outputResult.threats);
      }
    }

    // Attach scan metadata
    response._shield = {
      scanned: true,
      stats: shield.getStats()
    };

    return response;
  };

  client._shield = shield;
  return client;
}

function extractAnthropicText(msg) {
  if (typeof msg.content === 'string') return msg.content;
  if (Array.isArray(msg.content)) {
    return msg.content.map(b => b.text || '').join(' ');
  }
  return '';
}

function setAnthropicText(msg, text) {
  if (typeof msg.content === 'string') {
    msg.content = text;
  } else if (Array.isArray(msg.content) && msg.content.length === 1) {
    msg.content[0].text = text;
  }
}

// =========================================================================
// OpenAI SDK Integration
// =========================================================================

/**
 * Wraps an OpenAI client with threat scanning.
 *
 * Usage:
 *   const OpenAI = require('openai');
 *   const { shieldOpenAIClient } = require('agent-shield/src/integrations');
 *   const client = shieldOpenAIClient(new OpenAI(), { blockOnThreat: true });
 *   const completion = await client.chat.completions.create({ model: 'gpt-4', messages: [...] });
 */
function shieldOpenAIClient(client, options = {}) {
  const shield = new AgentShield({
    sensitivity: options.sensitivity || 'high',
    blockOnThreat: options.blockOnThreat || false
  });
  const piiRedactor = options.pii ? new PIIRedactor() : null;
  const onThreat = options.onThreat || null;

  const originalCreate = client.chat.completions.create.bind(client.chat.completions);

  client.chat.completions.create = async function shieldedCreate(params) {
    // Scan all messages
    for (const msg of params.messages || []) {
      const text = typeof msg.content === 'string' ? msg.content : (msg.content || []).map(p => p.text || '').join(' ');
      if (!text) continue;

      if (piiRedactor && msg.role === 'user') {
        const piiResult = piiRedactor.redact(text);
        if (piiResult.count > 0) {
          msg.content = piiResult.redacted;
        }
      }

      const result = shield.scanInput(text);
      if (result.threats.length > 0 && onThreat) {
        onThreat({ phase: 'input', role: msg.role, threats: result.threats });
      }
      if (result.blocked) {
        throw new ShieldBlockError('Message blocked by Agent Shield', result.threats);
      }
    }

    const response = await originalCreate(params);

    // Scan output
    const outputText = response.choices?.[0]?.message?.content || '';
    if (outputText) {
      const outputResult = shield.scanOutput(outputText);
      if (outputResult.threats.length > 0 && onThreat) {
        onThreat({ phase: 'output', threats: outputResult.threats });
      }
      if (outputResult.blocked) {
        throw new ShieldBlockError('Response blocked by Agent Shield', outputResult.threats);
      }
    }

    response._shield = { scanned: true, stats: shield.getStats() };
    return response;
  };

  client._shield = shield;
  return client;
}

// =========================================================================
// Vercel AI SDK Integration
// =========================================================================

/**
 * Middleware for Vercel AI SDK's streamText/generateText.
 *
 * Usage:
 *   const { shieldVercelAI } = require('agent-shield/src/integrations');
 *   const middleware = shieldVercelAI({ blockOnThreat: true });
 *   const result = await generateText({ model, prompt, middleware });
 */
function shieldVercelAI(options = {}) {
  const shield = new AgentShield({
    sensitivity: options.sensitivity || 'high',
    blockOnThreat: options.blockOnThreat || false
  });
  const onThreat = options.onThreat || null;

  return {
    transformParams: async ({ params }) => {
      // Scan all messages
      for (const msg of params.messages || []) {
        const text = typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content);
        const result = shield.scanInput(text);
        if (result.threats.length > 0 && onThreat) {
          onThreat({ phase: 'input', threats: result.threats });
        }
        if (result.blocked) {
          throw new ShieldBlockError('Blocked by Agent Shield', result.threats);
        }
      }
      return params;
    },
    wrapGenerate: async ({ doGenerate }) => {
      const result = await doGenerate();
      const text = result.text || '';
      if (text) {
        const scanResult = shield.scanOutput(text);
        if (scanResult.threats.length > 0 && onThreat) {
          onThreat({ phase: 'output', threats: scanResult.threats });
        }
        if (scanResult.blocked) {
          throw new ShieldBlockError('Response blocked by Agent Shield', scanResult.threats);
        }
      }
      return result;
    }
  };
}

// =========================================================================
// Generic Fetch Wrapper
// =========================================================================

/**
 * Wraps fetch to scan request/response bodies for threats.
 *
 * Usage:
 *   const { shieldFetch } = require('agent-shield/src/integrations');
 *   const safeFetch = shieldFetch(fetch, { blockOnThreat: true });
 *   const response = await safeFetch('https://api.openai.com/...', { body: JSON.stringify(data) });
 */
function shieldFetch(fetchFn, options = {}) {
  const shield = new AgentShield({
    sensitivity: options.sensitivity || 'high',
    blockOnThreat: options.blockOnThreat || false
  });

  return async function shieldedFetch(url, init = {}) {
    // Scan request body
    if (init.body) {
      const bodyText = typeof init.body === 'string' ? init.body : JSON.stringify(init.body);
      const result = shield.scanInput(bodyText);
      if (result.blocked) {
        throw new ShieldBlockError('Request body blocked by Agent Shield', result.threats);
      }
    }

    const response = await fetchFn(url, init);
    return response;
  };
}

// =========================================================================
// Shared Error Class
// =========================================================================

class ShieldBlockError extends Error {
  constructor(message, threats = []) {
    super(message);
    this.name = 'ShieldBlockError';
    this.threats = threats;
    this.code = 'AGENT_SHIELD_BLOCKED';
  }
}

module.exports = {
  // LangChain
  ShieldCallbackHandler,

  // Anthropic
  shieldAnthropicClient,

  // OpenAI
  shieldOpenAIClient,

  // Vercel AI
  shieldVercelAI,

  // Generic
  shieldFetch,

  // Error
  ShieldBlockError
};
