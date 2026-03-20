/**
 * Agent Shield — ESM entry point
 *
 * Usage:
 *   import { AgentShield, scanText, expressMiddleware } from 'agent-shield';
 */
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const shield = require('./main.js');

// Re-export all named exports
export const {
  AgentShield,
  scanText,
  getPatterns,
  SEVERITY_ORDER,
  expressMiddleware,
  wrapAgent,
  shieldTools,
  extractTextFromBody,
  shieldAnthropicClient,
  shieldOpenAIClient,
  ShieldCallbackHandler,
  shieldVercelAI,
  CanaryTokenGenerator,
  PromptLeakDetector,
  PIIRedactor,
  ToolSequenceAnalyzer,
  PermissionBoundary,
  CircuitBreaker,
  RateLimiter,
  ShadowMode,
  createShieldError,
  deprecationWarning,
  ERROR_CODES,
} = shield;

export default shield;
