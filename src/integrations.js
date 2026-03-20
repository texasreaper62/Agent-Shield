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
        try { this.onThreat({ phase: 'input', threats: result.threats, text: prompt }); } catch (e) { console.error('[Agent Shield] onThreat callback error:', e.message); }
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
      try { this.onThreat({ phase: 'output', threats: result.threats, text }); } catch (e) { console.error('[Agent Shield] onThreat callback error:', e.message); }
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
    if (result.threats.length > 0 && this.onThreat) {
      try { this.onThreat({ phase: 'tool_input', threats: result.threats }); } catch (e) { console.error('[Agent Shield] onThreat callback error:', e.message); }
    }
    if (result.blocked) {
      throw new ShieldBlockError('Tool input blocked by Agent Shield', result.threats);
    }
  }

  async handleToolEnd(output) {
    const text = typeof output === 'string' ? output : JSON.stringify(output);
    if (!text) return;

    const result = this.shield.scanInput(text);
    if (result.threats.length > 0 && this.onThreat) {
      try { this.onThreat({ phase: 'tool_output', threats: result.threats, text }); } catch (e) { console.error('[Agent Shield] onThreat callback error:', e.message); }
    }
    if (result.blocked) {
      throw new ShieldBlockError('Tool output blocked by Agent Shield — possible injection via tool response', result.threats);
    }
  }

  async handleChainEnd(outputs) {
    const text = typeof outputs === 'string' ? outputs : JSON.stringify(outputs);
    if (!text) return;

    const result = this.shield.scanOutput(text);
    if (result.threats.length > 0 && this.onThreat) {
      try { this.onThreat({ phase: 'chain_output', threats: result.threats }); } catch (e) { console.error('[Agent Shield] onThreat callback error:', e.message); }
    }
    if (result.blocked) {
      throw new ShieldBlockError('Chain output blocked by Agent Shield', result.threats);
    }
  }

  async handleAgentAction(action) {
    if (action && action.toolInput) {
      const text = typeof action.toolInput === 'string' ? action.toolInput : JSON.stringify(action.toolInput);
      const result = this.shield.scanInput(text);
      if (result.threats.length > 0 && this.onThreat) {
        try { this.onThreat({ phase: 'agent_action', tool: action.tool, threats: result.threats }); } catch (e) { console.error('[Agent Shield] onThreat callback error:', e.message); }
      }
      if (result.blocked) {
        throw new ShieldBlockError(`Agent action "${action.tool}" blocked by Agent Shield`, result.threats);
      }
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
        if (onThreat) { try { onThreat({ phase: 'input', role: msg.role, threats: result.threats }); } catch (e) { console.error('[Agent Shield] onThreat callback error:', e.message); } }
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

    // Scan output text
    const outputText = response.content?.map(b => b.text || '').join(' ') || '';
    if (outputText) {
      const outputResult = shield.scanOutput(outputText);
      if (outputResult.threats.length > 0 && onThreat) {
        try { onThreat({ phase: 'output', threats: outputResult.threats }); } catch (e) { console.error('[Agent Shield] onThreat callback error:', e.message); }
      }
      if (outputResult.blocked) {
        throw new ShieldBlockError('Response blocked by Agent Shield', outputResult.threats);
      }
    }

    // Scan tool_use blocks in response — tool calls can contain injection payloads
    if (response.content && Array.isArray(response.content)) {
      for (const block of response.content) {
        if (block.type === 'tool_use' && block.input) {
          const toolText = typeof block.input === 'string' ? block.input : JSON.stringify(block.input);
          const toolResult = shield.scanInput(toolText);
          if (toolResult.threats.length > 0) {
            if (onThreat) { try { onThreat({ phase: 'tool_call', tool: block.name, threats: toolResult.threats }); } catch (e) { console.error('[Agent Shield] onThreat callback error:', e.message); } }
            if (breaker) breaker.recordThreat(toolResult.threats.length);
            if (toolResult.blocked) {
              throw new ShieldBlockError(`Tool call "${block.name}" blocked by Agent Shield`, toolResult.threats);
            }
          }
        }
      }
    }

    // Scan tool_result messages in input — tool responses can inject threats
    for (const msg of params.messages || []) {
      if (msg.role === 'tool' || (Array.isArray(msg.content) && msg.content.some(b => b.type === 'tool_result'))) {
        const toolRespText = typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content);
        const toolRespResult = shield.scanInput(toolRespText);
        if (toolRespResult.threats.length > 0) {
          if (onThreat) { try { onThreat({ phase: 'tool_response', threats: toolRespResult.threats }); } catch (e) { console.error('[Agent Shield] onThreat callback error:', e.message); } }
          if (breaker) breaker.recordThreat(toolRespResult.threats.length);
          if (toolRespResult.blocked) {
            throw new ShieldBlockError('Tool response blocked by Agent Shield', toolRespResult.threats);
          }
        }
      }
    }

    // Attach scan metadata
    response._shield = {
      scanned: true,
      toolCallsScanned: (response.content || []).filter(b => b.type === 'tool_use').length,
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
  } else if (Array.isArray(msg.content)) {
    // Replace text across text blocks proportionally to preserve multi-block structure.
    // Non-text blocks (images, tool_use, etc.) are left untouched.
    const textBlocks = msg.content.filter(b => b.type === 'text' || b.text);
    if (textBlocks.length === 1) {
      textBlocks[0].text = text;
    } else if (textBlocks.length > 1) {
      // Split redacted text across blocks proportionally to original lengths
      const totalLen = textBlocks.reduce((sum, b) => sum + (b.text || '').length, 0);
      if (totalLen === 0) {
        textBlocks[0].text = text;
      } else {
        let offset = 0;
        for (let i = 0; i < textBlocks.length; i++) {
          const ratio = (textBlocks[i].text || '').length / totalLen;
          const chunkLen = i === textBlocks.length - 1
            ? text.length - offset
            : Math.round(text.length * ratio);
          textBlocks[i].text = text.slice(offset, offset + chunkLen);
          offset += chunkLen;
        }
      }
    }
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
  const breaker = options.circuitBreaker ? new CircuitBreaker(options.circuitBreaker) : null;
  const onThreat = options.onThreat || null;

  const originalCreate = client.chat.completions.create.bind(client.chat.completions);

  client.chat.completions.create = async function shieldedCreate(params) {
    // Circuit breaker check
    if (breaker) {
      const status = breaker.check();
      if (!status.allowed) {
        throw new ShieldBlockError(`Circuit breaker open: ${status.reason}`, []);
      }
    }

    // Scan all messages
    for (const msg of params.messages || []) {
      const text = typeof msg.content === 'string' ? msg.content : (msg.content || []).map(p => p.text || '').join(' ');
      if (!text) continue;

      // PII redaction
      if (piiRedactor && msg.role === 'user') {
        const piiResult = piiRedactor.redact(text);
        if (piiResult.count > 0) {
          msg.content = piiResult.redacted;
        }
      }

      const result = shield.scanInput(text);
      if (result.threats.length > 0) {
        if (onThreat) { try { onThreat({ phase: 'input', role: msg.role, threats: result.threats }); } catch (e) { console.error('[Agent Shield] onThreat callback error:', e.message); } }
        if (breaker) breaker.recordThreat(result.threats.length);
        if (result.blocked) {
          throw new ShieldBlockError('Message blocked by Agent Shield', result.threats);
        }
      }
    }

    // Scan system message if present
    const systemMsg = (params.messages || []).find(m => m.role === 'system');
    if (systemMsg && typeof systemMsg.content === 'string') {
      const sysResult = shield.scanInput(systemMsg.content);
      if (sysResult.blocked) {
        throw new ShieldBlockError('System message contains threats', sysResult.threats);
      }
    }

    // Scan tool/function response messages in input
    for (const msg of params.messages || []) {
      if (msg.role === 'tool' || msg.role === 'function') {
        const toolRespText = typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content);
        const toolRespResult = shield.scanInput(toolRespText);
        if (toolRespResult.threats.length > 0) {
          if (onThreat) { try { onThreat({ phase: 'tool_response', tool_call_id: msg.tool_call_id, threats: toolRespResult.threats }); } catch (e) { console.error('[Agent Shield] onThreat callback error:', e.message); } }
          if (breaker) breaker.recordThreat(toolRespResult.threats.length);
          if (toolRespResult.blocked) {
            throw new ShieldBlockError('Tool response blocked by Agent Shield', toolRespResult.threats);
          }
        }
      }
    }

    const response = await originalCreate(params);

    // Scan all output choices, not just the first
    for (const choice of response.choices || []) {
      const outputText = choice?.message?.content || '';
      if (outputText) {
        const outputResult = shield.scanOutput(outputText);
        if (outputResult.threats.length > 0 && onThreat) {
          try { onThreat({ phase: 'output', choiceIndex: choice.index, threats: outputResult.threats }); } catch (e) { console.error('[Agent Shield] onThreat callback error:', e.message); }
        }
        if (outputResult.blocked) {
          throw new ShieldBlockError('Response blocked by Agent Shield', outputResult.threats);
        }
      }

      // Scan tool calls in response
      const toolCalls = choice?.message?.tool_calls || choice?.message?.function_call ? [choice.message.function_call] : [];
      for (const tc of (choice?.message?.tool_calls || [])) {
        if (tc.function && tc.function.arguments) {
          const argsResult = shield.scanInput(tc.function.arguments);
          if (argsResult.threats.length > 0) {
            if (onThreat) { try { onThreat({ phase: 'tool_call', tool: tc.function.name, threats: argsResult.threats }); } catch (e) { console.error('[Agent Shield] onThreat callback error:', e.message); } }
            if (argsResult.blocked) {
              throw new ShieldBlockError(`Tool call "${tc.function.name}" blocked by Agent Shield`, argsResult.threats);
            }
          }
        }
      }
    }

    response._shield = {
      scanned: true,
      choicesScanned: (response.choices || []).length,
      stats: shield.getStats()
    };
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
          try { onThreat({ phase: 'input', threats: result.threats }); } catch (e) { console.error('[Agent Shield] onThreat callback error:', e.message); }
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
          try { onThreat({ phase: 'output', threats: scanResult.threats }); } catch (e) { console.error('[Agent Shield] onThreat callback error:', e.message); }
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
