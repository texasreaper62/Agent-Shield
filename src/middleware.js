'use strict';

/**
 * Agent Shield Middleware
 *
 * Plug-and-play middleware for common agent frameworks.
 * Wraps agent input/output pipelines with automatic threat scanning.
 */

const { AgentShield } = require('./index');
const { RateLimiter } = require('./circuit-breaker');
const { createShieldError } = require('./errors');

/**
 * Creates an Express/Connect-style middleware that scans request bodies
 * for AI-specific threats before they reach your agent endpoint.
 *
 * @param {object} [config] - AgentShield configuration.
 * @returns {Function} Express middleware function.
 *
 * @example
 * const express = require('express');
 * const { expressMiddleware } = require('agent-shield/src/middleware');
 *
 * const app = express();
 * app.use(express.json());
 * app.use(expressMiddleware({ blockOnThreat: true, blockThreshold: 'high' }));
 *
 * app.post('/agent', (req, res) => {
 *   // req.agentShield contains scan results
 *   if (req.agentShield.blocked) {
 *     return res.status(400).json({ error: 'Input blocked for safety' });
 *   }
 *   // ... process the agent request
 * });
 */
const expressMiddleware = (config = {}) => {
  const shield = new AgentShield({ blockOnThreat: true, ...config });

  return (req, res, next) => {
    if (!req.body) {
      req.agentShield = { status: 'safe', threats: [], blocked: false };
      return next();
    }

    // Extract text from common request body shapes
    const text = extractTextFromBody(req.body);

    if (!text) {
      req.agentShield = { status: 'safe', threats: [], blocked: false };
      return next();
    }

    const result = shield.scanInput(text, { source: 'http_request' });
    req.agentShield = result;

    if (result.blocked) {
      return res.status(400).json({
        error: 'Input blocked by Agent Shield',
        status: result.status,
        threats: result.threats.map(t => ({
          severity: t.severity,
          description: t.description
        }))
      });
    }

    next();
  };
};

/**
 * Creates a wrapper function that scans input/output around any async function.
 * Works with any agent framework — just wrap your agent's main function.
 *
 * @param {Function} agentFn - The agent function to wrap. Should accept (input) and return output.
 * @param {object} [config] - AgentShield configuration.
 * @returns {Function} Wrapped function with the same signature.
 *
 * @example
 * const { wrapAgent } = require('agent-shield/src/middleware');
 *
 * async function myAgent(input) {
 *   const response = await callLLM(input);
 *   return response;
 * }
 *
 * const protectedAgent = wrapAgent(myAgent, {
 *   blockOnThreat: true,
 *   logging: true
 * });
 *
 * // Use it the same way
 * const result = await protectedAgent('Hello, how are you?');
 */
const wrapAgent = (agentFn, config = {}) => {
  const shield = new AgentShield({ blockOnThreat: true, ...config });

  return async (input, ...rest) => {
    // Scan input
    const inputText = typeof input === 'string' ? input : JSON.stringify(input);
    const inputResult = shield.scanInput(inputText, { source: 'agent_input' });

    if (inputResult.blocked) {
      return {
        blocked: true,
        reason: 'Input blocked by Agent Shield',
        threats: inputResult.threats,
        output: null
      };
    }

    // Run the agent
    const output = await agentFn(input, ...rest);

    // Scan output
    const outputText = typeof output === 'string' ? output : JSON.stringify(output);
    const outputResult = shield.scanOutput(outputText, { source: 'agent_output' });

    if (outputResult.blocked) {
      return {
        blocked: true,
        reason: 'Output blocked by Agent Shield',
        threats: outputResult.threats,
        output: null
      };
    }

    return {
      blocked: false,
      threats: [...inputResult.threats, ...outputResult.threats],
      output
    };
  };
};

/**
 * Creates a tool-call interceptor that scans tool calls before execution.
 *
 * @param {object} tools - Map of tool name -> tool function.
 * @param {object} [config] - AgentShield configuration.
 * @returns {object} Map of tool name -> wrapped tool function.
 *
 * @example
 * const { shieldTools } = require('agent-shield/src/middleware');
 *
 * const tools = {
 *   bash: async (args) => exec(args.command),
 *   readFile: async (args) => fs.readFile(args.path, 'utf-8'),
 * };
 *
 * const protectedTools = shieldTools(tools, {
 *   blockOnThreat: true,
 *   logging: true
 * });
 *
 * // Use protectedTools in your agent — dangerous calls get blocked
 */
const shieldTools = (tools, config = {}) => {
  const shield = new AgentShield({ blockOnThreat: true, ...config });
  const wrapped = {};

  for (const [name, fn] of Object.entries(tools)) {
    wrapped[name] = async (args, ...rest) => {
      const result = shield.scanToolCall(name, args);

      if (result.blocked) {
        const error = createShieldError('AS-INT-004', {
          toolName: name,
          threats: result.threats.map(t => t.description)
        });
        error.message = `[Agent Shield AS-INT-004] Tool call "${name}" blocked: ${result.threats.map(t => t.description).join('; ')}`;
        error.agentShield = result;
        throw error;
      }

      return fn(args, ...rest);
    };
  }

  return wrapped;
};

/**
 * Extracts scannable text from common request body formats.
 * @param {object} body
 * @returns {string|null}
 */
const extractTextFromBody = (body) => {
  if (!body || (typeof body !== 'object' && typeof body !== 'string')) return null;
  if (typeof body === 'string') return body;

  // OpenAI-style messages array
  if (body.messages && Array.isArray(body.messages)) {
    return body.messages
      .map(m => typeof m.content === 'string' ? m.content : JSON.stringify(m.content))
      .join('\n');
  }

  // Single message/prompt field
  if (body.message) return typeof body.message === 'string' ? body.message : JSON.stringify(body.message);
  if (body.prompt) return typeof body.prompt === 'string' ? body.prompt : JSON.stringify(body.prompt);
  if (body.input) return typeof body.input === 'string' ? body.input : JSON.stringify(body.input);
  if (body.query) return typeof body.query === 'string' ? body.query : JSON.stringify(body.query);
  if (body.text) return typeof body.text === 'string' ? body.text : JSON.stringify(body.text);

  // Fallback: stringify the whole body
  const str = JSON.stringify(body);
  return str.length > 20 ? str : null;
};

/**
 * Creates rate-limiting middleware that returns 429 responses when limits are exceeded.
 * Includes backpressure headers (X-RateLimit-Remaining, X-RateLimit-Limit, Retry-After).
 *
 * @param {object} [options]
 * @param {number} [options.maxRequests=100] - Max requests per window.
 * @param {number} [options.windowMs=60000] - Window size in ms (default: 1 minute).
 * @param {number} [options.maxThreatsPerWindow=10] - Max threats before anomaly flag.
 * @param {Function} [options.onLimit] - Callback when limit is hit.
 * @param {boolean} [options.includeBackpressureHeaders=true] - Add rate limit headers to all responses.
 * @returns {Function} Express middleware function.
 *
 * @example
 * const { rateLimitMiddleware } = require('agent-shield/src/middleware');
 * app.use(rateLimitMiddleware({ maxRequests: 50, windowMs: 60000 }));
 */
const rateLimitMiddleware = (options = {}) => {
  const includeHeaders = options.includeBackpressureHeaders !== false;
  const limiter = new RateLimiter({
    maxRequests: options.maxRequests || 100,
    windowMs: options.windowMs || 60000,
    maxThreatsPerWindow: options.maxThreatsPerWindow || 10,
    onLimit: options.onLimit || null,
    onAnomaly: options.onAnomaly || null
  });

  return (req, res, next) => {
    const check = limiter.recordRequest();

    // Always set backpressure headers so callers can see remaining capacity
    if (includeHeaders) {
      res.setHeader('X-RateLimit-Limit', limiter.maxRequests);
      res.setHeader('X-RateLimit-Remaining', Math.max(0, check.remaining));
    }

    if (!check.allowed) {
      const retryAfterSec = Math.ceil(limiter.windowMs / 1000);
      res.setHeader('Retry-After', retryAfterSec);
      return res.status(429).json({
        error: 'Too Many Requests',
        message: check.reason,
        retryAfter: retryAfterSec
      });
    }

    // Expose limiter on request for downstream threat recording
    req.agentShieldRateLimiter = limiter;
    next();
  };
};

/**
 * Creates a combined Express middleware that applies rate limiting, threat scanning,
 * and backpressure headers in a single middleware call.
 *
 * @param {object} [config] - AgentShield + rate limiter configuration.
 * @param {number} [config.maxRequests=100] - Rate limit: max requests per window.
 * @param {number} [config.windowMs=60000] - Rate limit: window size in ms.
 * @param {boolean} [config.includeBackpressureHeaders=true] - Add rate limit headers.
 * @returns {Function} Express middleware function.
 *
 * @example
 * app.use(shieldMiddleware({ blockOnThreat: true, maxRequests: 50 }));
 */
const shieldMiddleware = (config = {}) => {
  const rateLimiter = rateLimitMiddleware({
    maxRequests: config.maxRequests,
    windowMs: config.windowMs,
    maxThreatsPerWindow: config.maxThreatsPerWindow,
    includeBackpressureHeaders: config.includeBackpressureHeaders,
    onLimit: config.onLimit,
    onAnomaly: config.onAnomaly
  });
  const scanner = expressMiddleware(config);

  return (req, res, next) => {
    // Rate limit first
    rateLimiter(req, res, (err) => {
      if (err) return next(err);
      // Then scan
      scanner(req, res, (scanErr) => {
        if (scanErr) return next(scanErr);
        // Record threats in rate limiter for anomaly detection
        if (req.agentShield && req.agentShield.threats && req.agentShield.threats.length > 0) {
          if (req.agentShieldRateLimiter) {
            req.agentShieldRateLimiter.recordThreat(req.agentShield.threats.length);
          }
        }
        next();
      });
    });
  };
};

module.exports = { expressMiddleware, wrapAgent, shieldTools, extractTextFromBody, rateLimitMiddleware, shieldMiddleware };
