'use strict';

/**
 * Agent Shield — Causal Intent Graph (L5)
 *
 * Traces causality through agent interactions. Builds a directed graph of:
 * user intent → LLM reasoning → tool call → tool output → next action.
 *
 * When an action doesn't causally connect to the original intent, it's an
 * attack — regardless of whether any pattern matched.
 *
 * All processing runs locally — no data ever leaves your environment.
 *
 * @module intent-graph
 */

const crypto = require('crypto');

// =========================================================================
// TOPIC SIMILARITY
// =========================================================================

/**
 * Extract topic keywords from text.
 * @param {string} text
 * @returns {Set<string>}
 */
function extractTopics(text) {
  const words = (text || '').toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 3);
  return new Set(words);
}

/**
 * Jaccard similarity between two sets.
 * @param {Set} a
 * @param {Set} b
 * @returns {number}
 */
function jaccardSimilarity(a, b) {
  if (a.size === 0 && b.size === 0) return 1;
  const intersection = new Set([...a].filter(x => b.has(x)));
  const union = new Set([...a, ...b]);
  return union.size > 0 ? intersection.size / union.size : 0;
}

// =========================================================================
// INTENT CATEGORIES
// =========================================================================

const TOOL_CATEGORIES = {
  data_read: /(?:read|get|fetch|query|select|search|find|list|show|cat|head|tail)/i,
  data_write: /(?:write|create|update|insert|put|set|modify|edit|append)/i,
  data_delete: /(?:delete|remove|drop|truncate|destroy|purge|clear|rm)/i,
  network: /(?:http|fetch|curl|wget|request|post|send|socket|connect|upload|download)/i,
  filesystem: /(?:file|fs|read.?file|write.?file|mkdir|readdir|stat|path)/i,
  execution: /(?:exec|spawn|shell|bash|cmd|run|eval|process|terminal)/i,
  auth: /(?:login|auth|token|credential|password|secret|key|oauth|session)/i,
  communication: /(?:email|mail|message|notify|slack|send|sms|chat|post)/i
};

/**
 * Categorize a tool name.
 * @param {string} toolName
 * @returns {string}
 */
function categorizeTool(toolName) {
  for (const [category, pattern] of Object.entries(TOOL_CATEGORIES)) {
    if (pattern.test(toolName)) return category;
  }
  return 'unknown';
}

// =========================================================================
// CAUSAL CHAIN RULES — which transitions are suspicious
// =========================================================================

const SUSPICIOUS_TRANSITIONS = [
  { from: 'auth', to: 'network', severity: 'critical', reason: 'Credential access followed by outbound network call — potential exfiltration.' },
  { from: 'auth', to: 'communication', severity: 'critical', reason: 'Credential access followed by communication — potential credential leak.' },
  { from: 'data_read', to: 'network', severity: 'high', reason: 'Data read followed by network call — potential data exfiltration.' },
  { from: 'filesystem', to: 'network', severity: 'high', reason: 'Filesystem access followed by network call — potential file exfiltration.' },
  { from: 'filesystem', to: 'execution', severity: 'high', reason: 'File operation followed by execution — potential malicious script execution.' },
  { from: 'data_read', to: 'communication', severity: 'high', reason: 'Data read followed by communication — potential data leak via messaging.' },
  { from: 'execution', to: 'network', severity: 'critical', reason: 'Code execution followed by network call — potential reverse shell or C2.' },
  { from: 'data_delete', to: 'data_delete', severity: 'high', reason: 'Multiple delete operations — potential destructive attack or evidence cleanup.' }
];

// =========================================================================
// IntentGraph
// =========================================================================

/**
 * Causal intent graph. Tracks the chain of actions from user intent to
 * agent execution and detects causal breaks.
 */
class IntentGraph {
  /**
   * @param {object} [options]
   * @param {number} [options.similarityThreshold=0.1] - Min topic similarity for causal link.
   * @param {number} [options.maxNodes=200] - Max nodes in the graph before pruning.
   */
  constructor(options = {}) {
    this.similarityThreshold = options.similarityThreshold || 0.1;
    this.maxNodes = options.maxNodes || 200;

    /** @type {Array<object>} Nodes in the graph */
    this.nodes = [];
    /** @type {Array<{ from: number, to: number, type: string }>} Edges */
    this.edges = [];
    /** @type {object|null} The current user intent */
    this.currentIntent = null;
    /** @type {Array<object>} Detected anomalies */
    this.anomalies = [];
  }

  /**
   * Set the user's original intent for the current interaction.
   *
   * @param {string} intentText - The user's request/query.
   * @returns {{ nodeId: number, topics: Set<string> }}
   */
  setIntent(intentText) {
    const nodeId = this._addNode({
      type: 'intent',
      text: intentText,
      topics: extractTopics(intentText),
      timestamp: Date.now()
    });
    this.currentIntent = this.nodes[nodeId];
    return { nodeId, topics: this.currentIntent.topics };
  }

  /**
   * Record a tool call and analyze its causal connection to the intent.
   *
   * @param {string} toolName - Tool being called.
   * @param {*} args - Tool arguments.
   * @param {string} [reason] - LLM's stated reason for the call.
   * @returns {{ nodeId: number, causalScore: number, suspicious: boolean, violations: Array<object> }}
   */
  recordToolCall(toolName, args, reason) {
    const argsStr = typeof args === 'string' ? args : JSON.stringify(args || {});
    const combinedText = `${toolName} ${argsStr} ${reason || ''}`;
    const topics = extractTopics(combinedText);
    const category = categorizeTool(toolName);

    const nodeId = this._addNode({
      type: 'tool_call',
      toolName,
      args: argsStr.substring(0, 500),
      reason: reason || '',
      topics,
      category,
      timestamp: Date.now()
    });

    // Link to previous node
    if (this.nodes.length > 1) {
      this.edges.push({ from: nodeId - 1, to: nodeId, type: 'sequence' });
    }

    // Analyze causal connection to intent
    const violations = [];
    let causalScore = 0;

    if (this.currentIntent) {
      causalScore = jaccardSimilarity(this.currentIntent.topics, topics);

      // Check if action is causally connected to intent
      if (causalScore < this.similarityThreshold && this.nodes.length > 2) {
        violations.push({
          type: 'causal_break',
          severity: 'high',
          toolName,
          causalScore,
          description: `Tool "${toolName}" has no topical connection to user intent (similarity: ${(causalScore * 100).toFixed(1)}%). Possible hijacked action.`
        });
      }
    }

    // Check suspicious transitions
    const prevToolNode = this._findPreviousToolNode(nodeId);
    if (prevToolNode) {
      for (const rule of SUSPICIOUS_TRANSITIONS) {
        if (prevToolNode.category === rule.from && category === rule.to) {
          violations.push({
            type: 'suspicious_transition',
            severity: rule.severity,
            from: `${prevToolNode.toolName} (${rule.from})`,
            to: `${toolName} (${rule.to})`,
            description: rule.reason
          });
        }
      }
    }

    // Record anomalies
    for (const v of violations) {
      this.anomalies.push({ ...v, nodeId, timestamp: Date.now() });
    }

    return {
      nodeId,
      causalScore: Math.round(causalScore * 1000) / 1000,
      suspicious: violations.length > 0,
      violations
    };
  }

  /**
   * Record a tool's output.
   *
   * @param {string} toolName
   * @param {*} output
   * @returns {{ nodeId: number }}
   */
  recordToolOutput(toolName, output) {
    const outputStr = typeof output === 'string' ? output : JSON.stringify(output || {});
    const nodeId = this._addNode({
      type: 'tool_output',
      toolName,
      output: outputStr.substring(0, 500),
      topics: extractTopics(outputStr),
      timestamp: Date.now()
    });

    if (this.nodes.length > 1) {
      this.edges.push({ from: nodeId - 1, to: nodeId, type: 'output' });
    }

    return { nodeId };
  }

  /**
   * Get the full causal chain from intent to current node.
   * @returns {Array<object>}
   */
  getChain() {
    return this.nodes.map((node, i) => ({
      id: i,
      type: node.type,
      toolName: node.toolName || null,
      category: node.category || null,
      causalScore: node.type === 'intent' ? 1 :
        (this.currentIntent ? jaccardSimilarity(this.currentIntent.topics, node.topics) : 0),
      timestamp: node.timestamp
    }));
  }

  /**
   * Get all detected anomalies.
   * @returns {Array<object>}
   */
  getAnomalies() {
    return [...this.anomalies];
  }

  /**
   * Get a risk assessment of the current chain.
   * @returns {{ riskLevel: string, score: number, anomalyCount: number, chainLength: number }}
   */
  getRiskAssessment() {
    const criticals = this.anomalies.filter(a => a.severity === 'critical').length;
    const highs = this.anomalies.filter(a => a.severity === 'high').length;
    const score = Math.max(0, 100 - criticals * 30 - highs * 15);
    const riskLevel = criticals > 0 ? 'critical' : highs > 0 ? 'high' : score < 70 ? 'medium' : 'safe';

    return {
      riskLevel,
      score,
      anomalyCount: this.anomalies.length,
      chainLength: this.nodes.length
    };
  }

  /**
   * Reset the graph for a new interaction.
   */
  reset() {
    this.nodes = [];
    this.edges = [];
    this.currentIntent = null;
    this.anomalies = [];
  }

  // -----------------------------------------------------------------------
  // Private
  // -----------------------------------------------------------------------

  /** @private */
  _addNode(node) {
    const id = this.nodes.length;
    node.id = id;
    this.nodes.push(node);
    if (this.nodes.length > this.maxNodes) {
      this.nodes = this.nodes.slice(-this.maxNodes);
      this.edges = this.edges.filter(e => e.from >= 0 && e.to >= 0);
    }
    return id;
  }

  /** @private */
  _findPreviousToolNode(beforeId) {
    for (let i = beforeId - 1; i >= 0; i--) {
      if (this.nodes[i] && this.nodes[i].type === 'tool_call') return this.nodes[i];
    }
    return null;
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  IntentGraph,
  extractTopics,
  jaccardSimilarity,
  categorizeTool,
  TOOL_CATEGORIES,
  SUSPICIOUS_TRANSITIONS
};
