'use strict';

/**
 * Agent Shield — Attack Surface Mapper (L5)
 *
 * Automatically analyzes an agent's complete configuration — tool definitions,
 * permissions, MCP connections, model, system prompt — and discovers every
 * possible attack path via graph traversal.
 *
 * Not "scan for known patterns" but "enumerate all possible exploitation chains."
 *
 * All processing runs locally — no data ever leaves your environment.
 *
 * @module attack-surface
 */

const { scanText } = require('./detector-core');

// =========================================================================
// RISK WEIGHTS
// =========================================================================

const CAPABILITY_RISK = {
  code_execution: 10,
  filesystem_write: 9,
  filesystem_read: 7,
  network_outbound: 8,
  network_inbound: 6,
  database_write: 8,
  database_read: 6,
  credential_access: 10,
  communication: 7,
  process_management: 9,
  package_management: 8,
  system_config: 9,
  user_impersonation: 10,
  agent_delegation: 7,
  memory_write: 6,
  scheduling: 5
};

const CAPABILITY_PATTERNS = {
  code_execution: /(?:exec|spawn|shell|bash|cmd|eval|Function|child_process|terminal|run\s+command)/i,
  filesystem_write: /(?:write|create|mkdir|append|save|put).*(?:file|fs|disk|path)/i,
  filesystem_read: /(?:read|open|cat|head|tail|get).*(?:file|fs|disk|path)/i,
  network_outbound: /(?:http|fetch|curl|wget|request|post|send|upload|socket\.connect)/i,
  network_inbound: /(?:listen|serve|bind|accept|server)/i,
  database_write: /(?:insert|update|delete|drop|alter|create\s+table)/i,
  database_read: /(?:select|query|find|aggregate|search).*(?:db|database|sql|mongo|redis)/i,
  credential_access: /(?:secret|credential|password|token|key|env|auth|oauth|session)/i,
  communication: /(?:email|mail|message|sms|slack|teams|notify|send\s+message)/i,
  process_management: /(?:kill|spawn|fork|process|pid|signal|daemon)/i,
  package_management: /(?:install|npm|pip|apt|brew|package|deploy|publish)/i,
  system_config: /(?:config|settings|env|environment|registry|sysctl)/i,
  user_impersonation: /(?:impersonate|act\s+as|assume\s+role|sudo|su\s)/i,
  agent_delegation: /(?:delegate|forward|relay|dispatch|hand\s*off)/i,
  memory_write: /(?:remember|store|save|persist|memo|context\s+write)/i,
  scheduling: /(?:cron|schedule|timer|interval|at\s+\d|recurring)/i
};

// =========================================================================
// AttackSurfaceMapper
// =========================================================================

/**
 * Maps the complete attack surface of an agent deployment.
 */
class AttackSurfaceMapper {
  /**
   * @param {object} [options]
   * @param {number} [options.maxChainDepth=5] - Max depth for attack chain enumeration.
   */
  constructor(options = {}) {
    this.maxChainDepth = options.maxChainDepth || 5;
  }

  /**
   * Map the attack surface of an agent configuration.
   *
   * @param {object} config
   * @param {Array<object>} config.tools - Tool definitions with name, description, permissions.
   * @param {Array<object>} [config.mcpServers] - MCP server connections.
   * @param {string} [config.systemPrompt] - The agent's system prompt.
   * @param {object} [config.permissions] - Agent-level permissions.
   * @param {string} [config.model] - Model being used.
   * @returns {object} Attack surface map with paths, risk scores, and recommendations.
   */
  map(config) {
    const tools = config.tools || [];
    const mcpServers = config.mcpServers || [];
    const systemPrompt = config.systemPrompt || '';
    const permissions = config.permissions || {};

    // 1. Inventory capabilities
    const capabilities = this._inventoryCapabilities(tools);

    // 2. Build adjacency graph
    const graph = this._buildGraph(tools, capabilities);

    // 3. Find all attack paths
    const attackPaths = this._enumerateAttackPaths(graph, capabilities);

    // 4. Score each path
    const scoredPaths = attackPaths.map(path => ({
      ...path,
      score: this._scoreAttackPath(path)
    })).sort((a, b) => b.score - a.score);

    // 5. Analyze system prompt
    const promptRisks = this._analyzeSystemPrompt(systemPrompt);

    // 6. Analyze MCP server connections
    const serverRisks = this._analyzeServers(mcpServers);

    // 7. Find permission gaps
    const permissionGaps = this._findPermissionGaps(tools, permissions);

    // 8. Generate overall risk assessment
    const overallScore = this._calculateOverallScore(scoredPaths, promptRisks, serverRisks, permissionGaps);

    return {
      summary: {
        toolCount: tools.length,
        serverCount: mcpServers.length,
        capabilityCount: Object.keys(capabilities).length,
        attackPathCount: scoredPaths.length,
        criticalPaths: scoredPaths.filter(p => p.score >= 80).length,
        overallRiskScore: overallScore,
        riskLevel: overallScore >= 80 ? 'critical' : overallScore >= 60 ? 'high' : overallScore >= 40 ? 'medium' : 'low'
      },
      capabilities,
      attackPaths: scoredPaths.slice(0, 20), // Top 20 most dangerous
      promptRisks,
      serverRisks,
      permissionGaps,
      recommendations: this._generateRecommendations(scoredPaths, capabilities, permissionGaps)
    };
  }

  // -----------------------------------------------------------------------
  // Analysis methods
  // -----------------------------------------------------------------------

  /**
   * Inventory all capabilities across tools.
   * @private
   */
  _inventoryCapabilities(tools) {
    const capabilities = {};
    for (const tool of tools) {
      const combined = `${tool.name || ''} ${tool.description || ''} ${JSON.stringify(tool.permissions || [])}`;
      for (const [cap, pattern] of Object.entries(CAPABILITY_PATTERNS)) {
        if (pattern.test(combined)) {
          if (!capabilities[cap]) capabilities[cap] = [];
          capabilities[cap].push({
            toolName: tool.name || 'unknown',
            risk: CAPABILITY_RISK[cap] || 5
          });
        }
      }
    }
    return capabilities;
  }

  /**
   * Build an adjacency graph of tool capabilities.
   * @private
   */
  _buildGraph(tools, capabilities) {
    const nodes = tools.map(t => ({
      name: t.name || 'unknown',
      capabilities: [],
      risk: 0
    }));

    // Assign capabilities to nodes
    for (const [cap, toolList] of Object.entries(capabilities)) {
      for (const entry of toolList) {
        const node = nodes.find(n => n.name === entry.toolName);
        if (node) {
          node.capabilities.push(cap);
          node.risk = Math.max(node.risk, entry.risk);
        }
      }
    }

    // Build edges (which tools can chain to which)
    const edges = [];
    for (let i = 0; i < nodes.length; i++) {
      for (let j = 0; j < nodes.length; j++) {
        if (i === j) continue;
        // A tool that reads can chain to a tool that sends
        const canChain = this._canChain(nodes[i].capabilities, nodes[j].capabilities);
        if (canChain) {
          edges.push({ from: i, to: j, reason: canChain });
        }
      }
    }

    return { nodes, edges };
  }

  /**
   * Determine if tool A's output can meaningfully chain to tool B's input.
   * @private
   */
  _canChain(capsA, capsB) {
    // Data read → network send (exfiltration)
    if ((capsA.includes('filesystem_read') || capsA.includes('database_read') || capsA.includes('credential_access'))
        && (capsB.includes('network_outbound') || capsB.includes('communication'))) {
      return 'data_exfiltration';
    }
    // Credential access → impersonation
    if (capsA.includes('credential_access') && capsB.includes('user_impersonation')) {
      return 'privilege_escalation';
    }
    // Filesystem write → code execution
    if (capsA.includes('filesystem_write') && capsB.includes('code_execution')) {
      return 'write_then_execute';
    }
    // Network inbound → code execution
    if (capsA.includes('network_inbound') && capsB.includes('code_execution')) {
      return 'remote_code_execution';
    }
    // Agent delegation → any high-risk capability
    if (capsA.includes('agent_delegation') && capsB.some(c => (CAPABILITY_RISK[c] || 0) >= 8)) {
      return 'delegation_escalation';
    }
    return null;
  }

  /**
   * Enumerate all attack paths up to maxChainDepth.
   * @private
   */
  _enumerateAttackPaths(graph, capabilities) {
    const paths = [];
    const { nodes, edges } = graph;

    // DFS from every node
    for (let start = 0; start < nodes.length; start++) {
      this._dfs(start, [start], edges, nodes, paths, new Set([start]));
    }

    return paths;
  }

  /**
   * DFS to find attack chains.
   * @private
   */
  _dfs(current, path, edges, nodes, results, visited) {
    if (path.length > this.maxChainDepth) return;

    // Record paths of length >= 2
    if (path.length >= 2) {
      const edge = edges.find(e => e.from === path[path.length - 2] && e.to === current);
      results.push({
        steps: path.map(i => ({
          tool: nodes[i].name,
          capabilities: nodes[i].capabilities,
          risk: nodes[i].risk
        })),
        chainType: edge ? edge.reason : 'sequential',
        length: path.length
      });
    }

    // Continue DFS
    for (const edge of edges) {
      if (edge.from === current && !visited.has(edge.to)) {
        visited.add(edge.to);
        this._dfs(edge.to, [...path, edge.to], edges, nodes, results, visited);
        visited.delete(edge.to);
      }
    }
  }

  /**
   * Score an attack path.
   * @private
   */
  _scoreAttackPath(path) {
    const maxRisk = Math.max(...path.steps.map(s => s.risk));
    const chainBonus = Math.min(path.length * 10, 30); // Longer chains = more dangerous
    const typeBonus = path.chainType === 'data_exfiltration' ? 20 :
                      path.chainType === 'privilege_escalation' ? 25 :
                      path.chainType === 'remote_code_execution' ? 30 :
                      path.chainType === 'write_then_execute' ? 25 : 10;
    return Math.min(100, maxRisk * 8 + chainBonus + typeBonus);
  }

  /**
   * Analyze system prompt for risks.
   * @private
   */
  _analyzeSystemPrompt(prompt) {
    if (!prompt) return { risks: [], score: 0 };
    const result = scanText(prompt);
    const risks = [];

    if (prompt.length < 50) {
      risks.push({ type: 'short_prompt', severity: 'medium', description: 'System prompt is very short. May lack sufficient safety constraints.' });
    }
    if (!/\b(?:never|must\s+not|do\s+not|forbidden|prohibited|restricted)\b/i.test(prompt)) {
      risks.push({ type: 'no_negative_constraints', severity: 'high', description: 'System prompt lacks explicit negative constraints (never, must not, forbidden).' });
    }
    if (!/\b(?:tool|function|action)\b/i.test(prompt) && !/\b(?:permission|allowed|authorized)\b/i.test(prompt)) {
      risks.push({ type: 'no_tool_constraints', severity: 'medium', description: 'System prompt does not mention tool/action constraints.' });
    }

    return { risks, score: risks.length * 15 };
  }

  /**
   * Analyze MCP server connections.
   * @private
   */
  _analyzeServers(servers) {
    const risks = [];
    for (const server of servers) {
      if (!server.auth && !server.oauthToken) {
        risks.push({ server: server.name || 'unknown', type: 'no_auth', severity: 'critical', description: 'MCP server has no authentication configured.' });
      }
      if (server.url && /^https?:\/\/0\.0\.0\.0|^https?:\/\/\[::\]/.test(server.url)) {
        risks.push({ server: server.name || 'unknown', type: 'open_binding', severity: 'critical', description: 'MCP server binds to all interfaces (0.0.0.0).' });
      }
    }
    return risks;
  }

  /**
   * Find permission gaps.
   * @private
   */
  _findPermissionGaps(tools, permissions) {
    const gaps = [];
    const allowedTools = permissions.allowedTools ? new Set(permissions.allowedTools) : null;

    for (const tool of tools) {
      // Tool not in allowlist
      if (allowedTools && !allowedTools.has(tool.name)) {
        gaps.push({ tool: tool.name, type: 'not_allowlisted', severity: 'medium', description: `Tool "${tool.name}" is available but not in the allowlist.` });
      }
      // Dangerous tool without explicit permission
      const combined = `${tool.name} ${tool.description || ''}`;
      if (CAPABILITY_PATTERNS.code_execution.test(combined) && !tool.requiresApproval) {
        gaps.push({ tool: tool.name, type: 'dangerous_no_approval', severity: 'critical', description: `Tool "${tool.name}" has code execution capability but doesn't require approval.` });
      }
      if (CAPABILITY_PATTERNS.credential_access.test(combined) && !tool.requiresApproval) {
        gaps.push({ tool: tool.name, type: 'credential_no_approval', severity: 'high', description: `Tool "${tool.name}" accesses credentials but doesn't require approval.` });
      }
    }
    return gaps;
  }

  /**
   * Calculate overall risk score.
   * @private
   */
  _calculateOverallScore(paths, promptRisks, serverRisks, permGaps) {
    const pathScore = paths.length > 0 ? Math.max(...paths.map(p => p.score)) : 0;
    const promptScore = promptRisks.score || 0;
    const serverScore = serverRisks.length * 20;
    const permScore = permGaps.filter(g => g.severity === 'critical').length * 25 +
                      permGaps.filter(g => g.severity === 'high').length * 15;
    return Math.min(100, Math.round((pathScore * 0.4 + promptScore * 0.2 + serverScore * 0.2 + permScore * 0.2)));
  }

  /**
   * Generate recommendations based on findings.
   * @private
   */
  _generateRecommendations(paths, capabilities, gaps) {
    const recs = [];

    if (capabilities.code_execution) {
      recs.push({ priority: 'critical', action: 'Sandbox all code execution tools. Require human approval for every execution.' });
    }
    if (capabilities.credential_access && capabilities.network_outbound) {
      recs.push({ priority: 'critical', action: 'Isolate credential-access tools from network tools. This combination enables data exfiltration.' });
    }
    if (capabilities.filesystem_write && capabilities.code_execution) {
      recs.push({ priority: 'critical', action: 'Prevent filesystem write tools from writing to executable paths. Block write-then-execute chains.' });
    }
    if (paths.some(p => p.chainType === 'data_exfiltration')) {
      recs.push({ priority: 'high', action: 'Add DLP (data loss prevention) scanning on all outbound network tool calls.' });
    }
    for (const gap of gaps.filter(g => g.severity === 'critical')) {
      recs.push({ priority: 'critical', action: `${gap.description} Add approval requirement or remove from agent.` });
    }
    if (recs.length === 0) {
      recs.push({ priority: 'low', action: 'No critical attack paths found. Continue monitoring.' });
    }

    return recs;
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  AttackSurfaceMapper,
  CAPABILITY_RISK,
  CAPABILITY_PATTERNS
};
