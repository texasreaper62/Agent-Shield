'use strict';

/**
 * Agent Shield — Preset Profiles, Config Builder & Copy-Paste Snippets
 *
 * Pre-built configurations for common use cases.
 * Users pick a preset and get sensible defaults + ready-to-use code.
 */

// =========================================================================
// Preset Profiles
// =========================================================================

const PRESETS = {
  chatbot: {
    name: 'Chatbot',
    description: 'Customer-facing chatbot with moderate security. Balances safety with user experience.',
    config: {
      sensitivity: 'high',
      blockOnThreat: true,
      blockThreshold: 'high',
      logging: true,
      modules: ['scanner', 'pii', 'circuitBreaker'],
      circuitBreaker: { threshold: 10, windowMs: 60000, cooldownMs: 120000 },
      rateLimiter: { maxRequests: 200, windowMs: 60000 },
      pii: { categories: ['email', 'ssn', 'credit_card', 'phone'] },
      permissions: { allowedTools: [], blockedTools: ['bash', 'shell', 'exec'] },
      cache: { enabled: true, maxSize: 500, ttlMs: 30000 }
    }
  },

  coding_agent: {
    name: 'Coding Agent',
    description: 'AI coding assistant with file/shell access. Strict tool boundaries.',
    config: {
      sensitivity: 'high',
      blockOnThreat: true,
      blockThreshold: 'high',
      logging: true,
      modules: ['scanner', 'toolGuard', 'circuitBreaker', 'canary'],
      circuitBreaker: { threshold: 5, windowMs: 60000, cooldownMs: 300000 },
      permissions: {
        allowedTools: ['readFile', 'writeFile', 'search', 'bash'],
        blockedTools: ['eval'],
        tools: {
          readFile: { blockPaths: ['/etc/', '/root/', '/home/*/.ssh/'], maxCallsPerMinute: 60 },
          writeFile: { blockPaths: ['/etc/', '/usr/', '/bin/'], blockArgs: ['.env', 'credentials'], maxCallsPerMinute: 30 },
          bash: { blockArgs: ['curl|bash', 'wget|sh', 'rm -rf', 'chmod 777'], maxCallsPerMinute: 20 }
        }
      },
      toolSequenceAnalysis: true
    }
  },

  rag_pipeline: {
    name: 'RAG Pipeline',
    description: 'Retrieval-augmented generation. Scans retrieved documents for indirect injection.',
    config: {
      sensitivity: 'high',
      blockOnThreat: true,
      blockThreshold: 'medium',
      logging: true,
      modules: ['scanner', 'encoding', 'pii', 'dlp', 'circuitBreaker'],
      circuitBreaker: { threshold: 8, windowMs: 60000, cooldownMs: 180000 },
      pii: { categories: ['email', 'ssn', 'credit_card', 'phone', 'address'] },
      dlp: { rules: [] },
      scanRetrievedContent: true,
      encoding: { detectBase64: true, detectHex: true, detectSteganography: true },
      cache: { enabled: true, maxSize: 2000, ttlMs: 300000 }
    }
  },

  customer_support: {
    name: 'Customer Support Bot',
    description: 'Handles sensitive customer data. Strong PII protection and DLP.',
    config: {
      sensitivity: 'high',
      blockOnThreat: true,
      blockThreshold: 'medium',
      logging: true,
      modules: ['scanner', 'pii', 'dlp', 'circuitBreaker', 'canary', 'conversation'],
      circuitBreaker: { threshold: 5, windowMs: 60000, cooldownMs: 300000 },
      rateLimiter: { maxRequests: 100, windowMs: 60000 },
      pii: { categories: ['email', 'ssn', 'credit_card', 'phone', 'address', 'name'] },
      dlp: { rules: [
        { name: 'account_number', pattern: 'ACCT-\\d{8,}', action: 'redact', replacement: '[ACCOUNT]' },
        { name: 'internal_id', pattern: 'INT-\\d{6}', action: 'redact', replacement: '[INTERNAL ID]' }
      ]},
      conversation: { fragmentationDetection: true, languageSwitchDetection: true }
    }
  },

  internal_tool: {
    name: 'Internal Tool',
    description: 'Internal-facing AI tool. Lighter security, focus on preventing accidents.',
    config: {
      sensitivity: 'medium',
      blockOnThreat: false,
      blockThreshold: 'critical',
      logging: true,
      modules: ['scanner', 'toolGuard'],
      circuitBreaker: { threshold: 20, windowMs: 60000, cooldownMs: 60000 },
      permissions: {
        allowedTools: ['search', 'readFile', 'writeFile', 'calculator', 'database'],
        blockedTools: ['bash', 'shell', 'exec', 'eval']
      }
    }
  },

  multi_agent: {
    name: 'Multi-Agent System',
    description: 'Multiple agents communicating. Agent firewall + delegation chains.',
    config: {
      sensitivity: 'high',
      blockOnThreat: true,
      blockThreshold: 'high',
      logging: true,
      modules: ['scanner', 'multiAgent', 'toolGuard', 'circuitBreaker', 'canary'],
      circuitBreaker: { threshold: 5, windowMs: 60000, cooldownMs: 300000 },
      agentFirewall: { trustedAgents: [], scanAllMessages: true },
      delegationChain: { maxDepth: 5, requireApproval: false },
      toolSequenceAnalysis: true
    }
  },

  high_security: {
    name: 'High Security',
    description: 'Maximum protection. All modules enabled. For regulated industries.',
    config: {
      sensitivity: 'high',
      blockOnThreat: true,
      blockThreshold: 'medium',
      logging: true,
      modules: ['scanner', 'pii', 'dlp', 'canary', 'toolGuard', 'circuitBreaker', 'conversation', 'encoding', 'multiAgent', 'watermark'],
      circuitBreaker: { threshold: 3, windowMs: 60000, cooldownMs: 600000 },
      rateLimiter: { maxRequests: 50, windowMs: 60000, maxThreatsPerWindow: 3 },
      pii: { categories: ['email', 'ssn', 'credit_card', 'phone', 'address', 'name', 'dob'] },
      permissions: {
        allowedTools: [],
        blockedTools: ['bash', 'shell', 'exec', 'eval', 'http_request']
      },
      conversation: { fragmentationDetection: true, languageSwitchDetection: true, behavioralFingerprinting: true },
      encoding: { detectBase64: true, detectHex: true, detectSteganography: true },
      watermark: { enabled: true },
      cache: { enabled: true, maxSize: 1000, ttlMs: 60000 }
    }
  },

  minimal: {
    name: 'Minimal',
    description: 'Bare minimum protection. Just injection scanning with low overhead.',
    config: {
      sensitivity: 'medium',
      blockOnThreat: false,
      blockThreshold: 'critical',
      logging: false,
      modules: ['scanner'],
      cache: { enabled: true, maxSize: 200, ttlMs: 10000 }
    }
  }
};

// =========================================================================
// Config Builder
// =========================================================================

class ConfigBuilder {
  constructor() {
    this.config = {
      sensitivity: 'high',
      blockOnThreat: true,
      blockThreshold: 'high',
      logging: true,
      modules: ['scanner']
    };
  }

  /**
   * Start from a preset.
   */
  fromPreset(presetName) {
    const preset = PRESETS[presetName];
    if (!preset) throw new Error(`Unknown preset: ${presetName}. Available: ${Object.keys(PRESETS).join(', ')}`);
    this.config = JSON.parse(JSON.stringify(preset.config));
    return this;
  }

  sensitivity(level) { this.config.sensitivity = level; return this; }
  blockOnThreat(enabled) { this.config.blockOnThreat = enabled; return this; }
  blockThreshold(level) { this.config.blockThreshold = level; return this; }
  logging(enabled) { this.config.logging = enabled; return this; }

  enableModule(mod) {
    if (!this.config.modules.includes(mod)) this.config.modules.push(mod);
    return this;
  }

  disableModule(mod) {
    this.config.modules = this.config.modules.filter(m => m !== mod);
    return this;
  }

  circuitBreaker(opts) { this.config.circuitBreaker = opts; return this; }
  rateLimiter(opts) { this.config.rateLimiter = opts; return this; }
  pii(opts) { this.config.pii = opts; return this; }
  dlp(opts) { this.config.dlp = opts; return this; }

  permissions(opts) { this.config.permissions = opts; return this; }
  cache(opts) { this.config.cache = opts; return this; }

  /**
   * Build the config object.
   */
  build() {
    return JSON.parse(JSON.stringify(this.config));
  }

  /**
   * Build and export as JSON string.
   */
  toJSON() {
    return JSON.stringify(this.config, null, 2);
  }
}

// =========================================================================
// Code Snippet Generator
// =========================================================================

class SnippetGenerator {
  /**
   * Generate setup code for a given preset/config.
   */
  static generate(presetOrConfig, framework = 'node') {
    const config = typeof presetOrConfig === 'string'
      ? (PRESETS[presetOrConfig] ? PRESETS[presetOrConfig].config : null)
      : presetOrConfig;

    if (!config) return null;

    switch (framework) {
      case 'node': return SnippetGenerator.nodeSnippet(config);
      case 'express': return SnippetGenerator.expressSnippet(config);
      case 'langchain': return SnippetGenerator.langchainSnippet(config);
      case 'anthropic': return SnippetGenerator.anthropicSnippet(config);
      case 'openai': return SnippetGenerator.openaiSnippet(config);
      case 'vercel': return SnippetGenerator.vercelSnippet(config);
      default: return SnippetGenerator.nodeSnippet(config);
    }
  }

  static nodeSnippet(config) {
    const lines = [];
    lines.push(`const { AgentShield } = require('agent-shield');`);

    if (config.modules?.includes('pii')) lines.push(`const { PIIRedactor } = require('agent-shield/src/pii');`);
    if (config.modules?.includes('circuitBreaker')) lines.push(`const { CircuitBreaker } = require('agent-shield/src/circuit-breaker');`);
    if (config.modules?.includes('canary')) lines.push(`const { CanaryTokens } = require('agent-shield/src/canary');`);
    if (config.modules?.includes('toolGuard')) lines.push(`const { PermissionBoundary, ToolSequenceAnalyzer } = require('agent-shield/src/tool-guard');`);

    lines.push('');
    lines.push(`const shield = new AgentShield({`);
    lines.push(`  sensitivity: '${config.sensitivity || 'high'}',`);
    lines.push(`  blockOnThreat: ${config.blockOnThreat !== false},`);
    lines.push(`  blockThreshold: '${config.blockThreshold || 'high'}'`);
    lines.push(`});`);

    if (config.circuitBreaker) {
      lines.push('');
      lines.push(`const breaker = new CircuitBreaker(${JSON.stringify(config.circuitBreaker)});`);
    }

    if (config.pii) {
      lines.push('');
      lines.push(`const pii = new PIIRedactor(${JSON.stringify(config.pii)});`);
    }

    lines.push('');
    lines.push(`// Scan user input`);
    lines.push(`const result = shield.scanInput(userMessage);`);
    lines.push(`if (result.blocked) {`);
    lines.push(`  console.log('Blocked:', result.threats);`);
    lines.push(`}`);

    return lines.join('\n');
  }

  static expressSnippet(config) {
    return `const { expressMiddleware } = require('agent-shield/src/middleware');

app.use('/api/agent', expressMiddleware({
  sensitivity: '${config.sensitivity || 'high'}',
  blockOnThreat: ${config.blockOnThreat !== false},
  blockThreshold: '${config.blockThreshold || 'high'}'
}));`;
  }

  static langchainSnippet(config) {
    return `const { ShieldCallbackHandler } = require('agent-shield/src/integrations');

const shieldHandler = new ShieldCallbackHandler({
  sensitivity: '${config.sensitivity || 'high'}',
  blockOnThreat: ${config.blockOnThreat !== false},
  onThreat: (info) => console.log('Threat detected:', info)
});

const chain = new LLMChain({
  llm,
  prompt,
  callbacks: [shieldHandler]
});`;
  }

  static anthropicSnippet(config) {
    return `const Anthropic = require('@anthropic-ai/sdk');
const { shieldAnthropicClient } = require('agent-shield/src/integrations');

const client = shieldAnthropicClient(new Anthropic(), {
  sensitivity: '${config.sensitivity || 'high'}',
  blockOnThreat: ${config.blockOnThreat !== false},
  pii: ${!!config.pii},
  onThreat: (info) => console.log('Threat:', info)
});

// Use client normally — all messages are scanned automatically
const msg = await client.messages.create({
  model: 'claude-sonnet-4-20250514',
  messages: [{ role: 'user', content: userInput }]
});`;
  }

  static openaiSnippet(config) {
    return `const OpenAI = require('openai');
const { shieldOpenAIClient } = require('agent-shield/src/integrations');

const client = shieldOpenAIClient(new OpenAI(), {
  sensitivity: '${config.sensitivity || 'high'}',
  blockOnThreat: ${config.blockOnThreat !== false},
  onThreat: (info) => console.log('Threat:', info)
});

// Use client normally — all messages are scanned automatically
const completion = await client.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: userInput }]
});`;
  }

  static vercelSnippet(config) {
    return `const { shieldVercelAI } = require('agent-shield/src/integrations');

const shieldMiddleware = shieldVercelAI({
  sensitivity: '${config.sensitivity || 'high'}',
  blockOnThreat: ${config.blockOnThreat !== false},
  onThreat: (info) => console.log('Threat:', info)
});

const result = await generateText({
  model,
  prompt: userInput,
  experimental_middleware: shieldMiddleware
});`;
  }

  /**
   * Get all available frameworks.
   */
  static getFrameworks() {
    return [
      { id: 'node', name: 'Node.js', description: 'Direct Node.js usage' },
      { id: 'express', name: 'Express.js', description: 'Express middleware' },
      { id: 'langchain', name: 'LangChain', description: 'LangChain callback handler' },
      { id: 'anthropic', name: 'Anthropic SDK', description: 'Claude API wrapper' },
      { id: 'openai', name: 'OpenAI SDK', description: 'OpenAI API wrapper' },
      { id: 'vercel', name: 'Vercel AI SDK', description: 'Vercel AI middleware' }
    ];
  }
}

// =========================================================================
// Preset Helpers
// =========================================================================

/**
 * Get all available presets.
 */
function getPresets() {
  return Object.entries(PRESETS).map(([key, val]) => ({
    key,
    name: val.name,
    description: val.description,
    modules: val.config.modules
  }));
}

/**
 * Get a specific preset config.
 */
function getPreset(name) {
  return PRESETS[name] || null;
}

module.exports = {
  PRESETS,
  ConfigBuilder,
  SnippetGenerator,
  getPresets,
  getPreset
};
