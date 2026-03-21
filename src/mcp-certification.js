'use strict';

/**
 * Agent Shield — MCP Security Certification & Trust Framework
 *
 * Three components that create a competitive moat:
 *
 * 1. AgentThreatIntelligence — continuously updated attack pattern corpus
 *    that gets better with every deployment. A data moat.
 *
 * 2. MCPCertification — "Agent Shield Certified" attestation for MCP servers.
 *    If every MCP server runs certification, Agent Shield becomes the standard.
 *
 * 3. CrossOrgAgentTrust — certificate authority for AI agents communicating
 *    across organizational boundaries. The "TLS for AI agents."
 *
 * All processing runs locally — no data ever leaves your environment.
 */

const crypto = require('crypto');

const LOG_PREFIX = '[Agent Shield]';

// =========================================================================
// Agent Threat Intelligence — the data moat
// =========================================================================

/** Built-in threat categories with severity weights. */
const THREAT_CATEGORIES = Object.freeze({
  prompt_injection: { severity: 'critical', weight: 1.0 },
  data_exfiltration: { severity: 'critical', weight: 1.0 },
  privilege_escalation: { severity: 'critical', weight: 0.95 },
  confused_deputy: { severity: 'high', weight: 0.9 },
  tool_abuse: { severity: 'high', weight: 0.85 },
  session_hijack: { severity: 'high', weight: 0.85 },
  delegation_attack: { severity: 'high', weight: 0.8 },
  prompt_leakage: { severity: 'medium', weight: 0.7 },
  rag_poisoning: { severity: 'medium', weight: 0.7 },
  behavioral_anomaly: { severity: 'medium', weight: 0.6 },
  resource_abuse: { severity: 'low', weight: 0.4 },
  policy_violation: { severity: 'low', weight: 0.3 }
});

/**
 * Local threat intelligence engine that learns from observed attacks.
 * Maintains a pattern corpus that improves detection over time.
 * All data stays local — nothing is ever transmitted.
 */
class AgentThreatIntelligence {
  /**
   * @param {object} [options]
   * @param {number} [options.maxPatterns=10000] - Max patterns to store
   * @param {number} [options.decayHalfLifeMs=604800000] - Pattern relevance decay (default 7 days)
   * @param {number} [options.minConfidence=0.6] - Min confidence for pattern to be active
   */
  constructor(options = {}) {
    this._maxPatterns = options.maxPatterns || 10000;
    this._decayHalfLife = options.decayHalfLifeMs || 604800000;
    this._minConfidence = options.minConfidence || 0.6;

    // Pattern corpus — the intelligence
    this._patterns = new Map(); // patternId → PatternEntry
    this._categoryStats = {};
    for (const cat of Object.keys(THREAT_CATEGORIES)) {
      this._categoryStats[cat] = { observed: 0, blocked: 0, bypassed: 0 };
    }

    // Attack timeline for trend analysis
    this._timeline = [];
    this._maxTimeline = 10000;

    this.stats = { patternsLearned: 0, attacksObserved: 0, trendsGenerated: 0 };
  }

  /**
   * Records an observed attack for intelligence gathering.
   * @param {object} attack
   * @param {string} attack.category - Threat category
   * @param {string} attack.pattern - Attack pattern/signature
   * @param {string} [attack.source] - Where the attack was detected
   * @param {object} [attack.context] - Additional context (tool, session, etc.)
   * @param {boolean} [attack.blocked=true] - Whether the attack was blocked
   * @returns {{ patternId: string, isNew: boolean, confidence: number }}
   */
  recordAttack(attack) {
    if (!attack.category || !attack.pattern) {
      throw new Error(`${LOG_PREFIX} recordAttack requires category and pattern`);
    }

    this.stats.attacksObserved++;
    const patternId = this._hashPattern(attack.category, attack.pattern);

    // Update category stats
    const catStats = this._categoryStats[attack.category];
    if (catStats) {
      catStats.observed++;
      if (attack.blocked !== false) catStats.blocked++;
      else catStats.bypassed++;
    }

    // Record in timeline
    this._timeline.push({
      timestamp: Date.now(),
      category: attack.category,
      patternId,
      blocked: attack.blocked !== false,
      source: attack.source || 'unknown'
    });
    if (this._timeline.length > this._maxTimeline) {
      this._timeline = this._timeline.slice(-Math.floor(this._maxTimeline * 0.75));
    }

    // Update or create pattern
    const existing = this._patterns.get(patternId);
    if (existing) {
      existing.hitCount++;
      existing.lastSeen = Date.now();
      existing.confidence = Math.min(1.0, existing.confidence + 0.05);
      if (attack.blocked === false) existing.bypassCount++;
      return { patternId, isNew: false, confidence: existing.confidence };
    }

    // New pattern
    const entry = {
      patternId,
      category: attack.category,
      pattern: attack.pattern,
      source: attack.source || 'unknown',
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      hitCount: 1,
      bypassCount: attack.blocked === false ? 1 : 0,
      confidence: 0.65,
      context: attack.context || {}
    };

    this._patterns.set(patternId, entry);
    this.stats.patternsLearned++;

    // Evict oldest patterns if at capacity
    if (this._patterns.size > this._maxPatterns) {
      this._evictOldest();
    }

    return { patternId, isNew: true, confidence: entry.confidence };
  }

  /**
   * Checks if input matches any known threat patterns.
   * @param {string} input - Text to check
   * @returns {{ matches: Array<{ patternId: string, category: string, confidence: number }>, riskScore: number }}
   */
  checkAgainstIntel(input) {
    const matches = [];
    const lowerInput = input.toLowerCase();

    for (const [_id, entry] of this._patterns) {
      if (entry.confidence < this._minConfidence) continue;
      const decayedConfidence = this._applyDecay(entry);
      if (decayedConfidence < this._minConfidence) continue;

      // Check if pattern appears in input
      if (lowerInput.includes(entry.pattern.toLowerCase())) {
        matches.push({
          patternId: entry.patternId,
          category: entry.category,
          confidence: decayedConfidence,
          hitCount: entry.hitCount,
          firstSeen: entry.firstSeen
        });
      }
    }

    // Calculate composite risk score
    let riskScore = 0;
    for (const match of matches) {
      const catWeight = (THREAT_CATEGORIES[match.category] || { weight: 0.5 }).weight;
      riskScore = Math.max(riskScore, match.confidence * catWeight);
    }

    return { matches, riskScore: Math.round(riskScore * 100) / 100 };
  }

  /**
   * Generates trend analysis from observed attacks.
   * @param {number} [windowMs=86400000] - Analysis window (default 24 hours)
   * @returns {{ topCategories: Array, attackRate: number, trendDirection: string, bypassRate: number }}
   */
  getTrends(windowMs = 86400000) {
    const cutoff = Date.now() - windowMs;
    const recent = this._timeline.filter(e => e.timestamp > cutoff);
    this.stats.trendsGenerated++;

    // Category breakdown
    const catCounts = {};
    let blocked = 0;
    let bypassed = 0;
    for (const event of recent) {
      catCounts[event.category] = (catCounts[event.category] || 0) + 1;
      if (event.blocked) blocked++;
      else bypassed++;
    }

    const topCategories = Object.entries(catCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([category, count]) => ({ category, count, percentage: Math.round(count / recent.length * 100) }));

    // Trend direction — compare first half vs second half
    const midpoint = cutoff + windowMs / 2;
    const firstHalf = recent.filter(e => e.timestamp < midpoint).length;
    const secondHalf = recent.filter(e => e.timestamp >= midpoint).length;
    let trendDirection = 'stable';
    if (secondHalf > firstHalf * 1.5) trendDirection = 'increasing';
    else if (secondHalf < firstHalf * 0.5) trendDirection = 'decreasing';

    return {
      topCategories,
      attackRate: recent.length > 0 ? Math.round(recent.length / (windowMs / 3600000) * 100) / 100 : 0,
      trendDirection,
      bypassRate: (blocked + bypassed) > 0 ? Math.round(bypassed / (blocked + bypassed) * 100) / 100 : 0,
      totalObserved: recent.length,
      window: { start: cutoff, end: Date.now() }
    };
  }

  /**
   * Exports the intelligence corpus for backup/transfer.
   * @returns {object} Serializable intelligence data
   */
  exportCorpus() {
    const patterns = [];
    for (const [_id, entry] of this._patterns) {
      patterns.push({ ...entry });
    }
    return {
      version: '1.0.0',
      exportedAt: Date.now(),
      stats: { ...this.stats },
      categoryStats: { ...this._categoryStats },
      patterns
    };
  }

  /**
   * Imports intelligence corpus from another instance.
   * @param {object} corpus - Output of exportCorpus()
   * @returns {{ imported: number, merged: number, skipped: number }}
   */
  importCorpus(corpus) {
    if (!corpus || !corpus.patterns) {
      throw new Error(`${LOG_PREFIX} Invalid corpus format`);
    }
    let imported = 0;
    let merged = 0;
    let skipped = 0;

    for (const entry of corpus.patterns) {
      const existing = this._patterns.get(entry.patternId);
      if (existing) {
        // Merge — take higher confidence and combined hit count
        existing.hitCount += entry.hitCount;
        existing.confidence = Math.max(existing.confidence, entry.confidence);
        if (entry.lastSeen > existing.lastSeen) existing.lastSeen = entry.lastSeen;
        merged++;
      } else if (this._patterns.size < this._maxPatterns) {
        this._patterns.set(entry.patternId, { ...entry });
        imported++;
      } else {
        skipped++;
      }
    }

    return { imported, merged, skipped };
  }

  /** @private */
  _hashPattern(category, pattern) {
    return crypto.createHash('sha256').update(`${category}:${pattern}`).digest('hex').substring(0, 16);
  }

  /** @private */
  _applyDecay(entry) {
    const age = Date.now() - entry.lastSeen;
    const decayFactor = Math.pow(0.5, age / this._decayHalfLife);
    return entry.confidence * decayFactor;
  }

  /** @private */
  _evictOldest() {
    let oldest = null;
    let oldestTime = Infinity;
    for (const [id, entry] of this._patterns) {
      if (entry.lastSeen < oldestTime) {
        oldestTime = entry.lastSeen;
        oldest = id;
      }
    }
    if (oldest) this._patterns.delete(oldest);
  }
}

// =========================================================================
// MCP Certification — "Agent Shield Certified"
// =========================================================================

/** Certification requirements — what an MCP server must have. */
const CERTIFICATION_REQUIREMENTS = Object.freeze([
  {
    id: 'AUTH_001',
    name: 'Per-User Authentication',
    category: 'authentication',
    severity: 'critical',
    description: 'MCP server must authenticate individual users, not just agents',
    check: (config) => config.enforceAuth !== false
  },
  {
    id: 'AUTH_002',
    name: 'Authorization Context Propagation',
    category: 'authentication',
    severity: 'critical',
    description: 'Authorization context must flow through all tool calls',
    check: (config) => config.contextPropagation !== false
  },
  {
    id: 'AUTH_003',
    name: 'Delegation Depth Limiting',
    category: 'authentication',
    severity: 'high',
    description: 'Agent delegation chains must be depth-limited',
    check: (config) => (config.maxDelegationDepth || 0) > 0 && (config.maxDelegationDepth || Infinity) <= 10
  },
  {
    id: 'SCAN_001',
    name: 'Tool Input Scanning',
    category: 'scanning',
    severity: 'critical',
    description: 'All tool call arguments must be scanned for injection',
    check: (config) => config.scanInputs !== false
  },
  {
    id: 'SCAN_002',
    name: 'Tool Output Scanning',
    category: 'scanning',
    severity: 'high',
    description: 'Tool results must be scanned before returning to user',
    check: (config) => config.scanOutputs !== false
  },
  {
    id: 'SCAN_003',
    name: 'Resource Content Scanning',
    category: 'scanning',
    severity: 'medium',
    description: 'MCP resources should be scanned before exposure',
    check: (config) => config.scanResources !== false
  },
  {
    id: 'RATE_001',
    name: 'Per-Session Rate Limiting',
    category: 'rate_limiting',
    severity: 'high',
    description: 'Tool calls must be rate-limited per session',
    check: (config) => (config.maxToolCallsPerSession || 0) > 0
  },
  {
    id: 'RATE_002',
    name: 'Token Budget Enforcement',
    category: 'rate_limiting',
    severity: 'medium',
    description: 'Sessions must have token/cost budgets',
    check: (config) => (config.maxTokenBudget || 0) > 0
  },
  {
    id: 'AUDIT_001',
    name: 'Audit Trail',
    category: 'audit',
    severity: 'critical',
    description: 'All security events must be logged to an audit trail',
    check: (config) => config.auditEnabled !== false
  },
  {
    id: 'AUDIT_002',
    name: 'Threat Event Callbacks',
    category: 'audit',
    severity: 'high',
    description: 'Security team must be notified of threats in real-time',
    check: (config) => typeof config.onThreat === 'function'
  },
  {
    id: 'CRYPTO_001',
    name: 'HMAC Context Signing',
    category: 'cryptography',
    severity: 'critical',
    description: 'Authorization contexts must be HMAC-signed to prevent forgery',
    check: (config) => config.signingKey && config.signingKey !== 'agent-shield-default-signing-key'
  },
  {
    id: 'CRYPTO_002',
    name: 'Ephemeral Token Credentials',
    category: 'cryptography',
    severity: 'high',
    description: 'Tool access should use ephemeral tokens, not static credentials',
    check: (config) => config.ephemeralTokens !== false
  },
  {
    id: 'BEHAV_001',
    name: 'Behavioral Monitoring',
    category: 'monitoring',
    severity: 'medium',
    description: 'Agent behavior should be profiled for anomaly detection',
    check: (config) => config.enableBehaviorMonitoring !== false
  },
  {
    id: 'STATE_001',
    name: 'Session State Machine',
    category: 'session',
    severity: 'high',
    description: 'Sessions must enforce valid state transitions',
    check: (config) => config.enableStateMachine !== false
  },
  {
    id: 'POLICY_001',
    name: 'Tool-Level Policies',
    category: 'policy',
    severity: 'high',
    description: 'Individual tools must have declared security policies',
    check: (config) => (config.registeredTools || 0) > 0
  }
]);

/** Certification levels based on score. */
const CERTIFICATION_LEVELS = Object.freeze({
  PLATINUM: { minScore: 95, label: 'Platinum', badge: '🛡️ Agent Shield Certified — Platinum' },
  GOLD: { minScore: 80, label: 'Gold', badge: '🛡️ Agent Shield Certified — Gold' },
  SILVER: { minScore: 65, label: 'Silver', badge: '🛡️ Agent Shield Certified — Silver' },
  BRONZE: { minScore: 50, label: 'Bronze', badge: '🛡️ Agent Shield Certified — Bronze' },
  NONE: { minScore: 0, label: 'Not Certified', badge: '⚠️ Not Certified' }
});

/**
 * Evaluates an MCP server configuration against Agent Shield certification requirements.
 */
class MCPCertification {
  /**
   * Runs certification audit against the provided configuration.
   * @param {object} config - MCP server security configuration
   * @returns {{ certified: boolean, level: string, score: number, badge: string, results: Array, recommendations: Array }}
   */
  static evaluate(config = {}) {
    const results = [];
    let totalWeight = 0;
    let earnedWeight = 0;

    const severityWeights = { critical: 3, high: 2, medium: 1 };

    for (const req of CERTIFICATION_REQUIREMENTS) {
      const weight = severityWeights[req.severity] || 1;
      totalWeight += weight;

      let passed = false;
      try {
        passed = req.check(config);
      } catch {
        passed = false;
      }

      if (passed) earnedWeight += weight;

      results.push({
        id: req.id,
        name: req.name,
        category: req.category,
        severity: req.severity,
        passed,
        description: req.description
      });
    }

    const score = Math.round(earnedWeight / totalWeight * 100);

    // Determine level
    let level = CERTIFICATION_LEVELS.NONE;
    for (const l of [CERTIFICATION_LEVELS.PLATINUM, CERTIFICATION_LEVELS.GOLD, CERTIFICATION_LEVELS.SILVER, CERTIFICATION_LEVELS.BRONZE]) {
      if (score >= l.minScore) { level = l; break; }
    }

    // Generate recommendations for failed checks
    const recommendations = results
      .filter(r => !r.passed)
      .sort((a, b) => (severityWeights[b.severity] || 0) - (severityWeights[a.severity] || 0))
      .map(r => ({
        id: r.id,
        priority: r.severity,
        action: r.description
      }));

    return {
      certified: score >= CERTIFICATION_LEVELS.BRONZE.minScore,
      level: level.label,
      score,
      badge: level.badge,
      timestamp: Date.now(),
      results,
      recommendations,
      summary: {
        total: results.length,
        passed: results.filter(r => r.passed).length,
        failed: results.filter(r => !r.passed).length,
        criticalFailures: results.filter(r => !r.passed && r.severity === 'critical').length
      }
    };
  }

  /**
   * Generates a certification report as formatted text.
   * @param {object} evaluation - Output of evaluate()
   * @returns {string}
   */
  static formatReport(evaluation) {
    const lines = [
      '',
      '═'.repeat(60),
      '  MCP Security Certification Report',
      '═'.repeat(60),
      '',
      `  Level: ${evaluation.badge}`,
      `  Score: ${evaluation.score}/100`,
      `  Date:  ${new Date(evaluation.timestamp).toISOString().substring(0, 10)}`,
      '',
      `  Results: ${evaluation.summary.passed}/${evaluation.summary.total} passed` +
        (evaluation.summary.criticalFailures > 0 ? ` (${evaluation.summary.criticalFailures} critical failures)` : ''),
      ''
    ];

    // Group by category
    const categories = {};
    for (const r of evaluation.results) {
      if (!categories[r.category]) categories[r.category] = [];
      categories[r.category].push(r);
    }

    for (const [cat, items] of Object.entries(categories)) {
      lines.push(`  ${cat.toUpperCase()}`);
      for (const item of items) {
        const icon = item.passed ? '✓' : '✗';
        lines.push(`    ${icon} [${item.id}] ${item.name}`);
      }
      lines.push('');
    }

    if (evaluation.recommendations.length > 0) {
      lines.push('  RECOMMENDATIONS');
      for (const rec of evaluation.recommendations) {
        lines.push(`    [${rec.priority.toUpperCase()}] ${rec.action}`);
      }
      lines.push('');
    }

    lines.push('═'.repeat(60));
    return lines.join('\n');
  }
}

// =========================================================================
// Cross-Organization Agent Trust — CA for AI agents
// =========================================================================

/**
 * Certificate authority for AI agents crossing organizational boundaries.
 * Issues, verifies, and revokes trust certificates for agents.
 *
 * When agents from different organizations need to interact via MCP,
 * they present their trust certificate to prove identity and capabilities.
 */
class CrossOrgAgentTrust {
  /**
   * @param {object} options
   * @param {string} options.orgId - Organization identifier
   * @param {string} options.signingKey - HMAC key for certificate signing
   * @param {number} [options.certificateTtlMs=86400000] - Certificate lifetime (default 24 hours)
   * @param {number} [options.maxCertificates=1000] - Max active certificates
   */
  constructor(options = {}) {
    if (!options.orgId) throw new Error(`${LOG_PREFIX} CrossOrgAgentTrust requires orgId`);
    if (!options.signingKey) throw new Error(`${LOG_PREFIX} CrossOrgAgentTrust requires signingKey`);

    this._orgId = options.orgId;
    this._signingKey = options.signingKey;
    this._certificateTtlMs = options.certificateTtlMs || 86400000;
    this._maxCertificates = options.maxCertificates || 1000;

    // Active certificates
    this._certificates = new Map(); // certId → certificate
    this._revokedCerts = new Set();
    this._trustedOrgs = new Map(); // orgId → { publicKey, trustLevel }

    this.stats = { issued: 0, verified: 0, rejected: 0, revoked: 0 };
  }

  /**
   * Issues a trust certificate for an agent.
   * @param {object} params
   * @param {string} params.agentId - Agent identity
   * @param {string[]} params.capabilities - What the agent can do
   * @param {string[]} [params.allowedOrgs] - Which orgs this agent can interact with ('*' = any)
   * @param {number} [params.trustLevel=5] - Trust level 1-10
   * @returns {object} Signed certificate
   */
  issueCertificate(params) {
    if (!params.agentId) throw new Error(`${LOG_PREFIX} issueCertificate requires agentId`);

    const certId = crypto.randomUUID();
    const now = Date.now();

    const certificate = {
      certId,
      version: '1.0',
      issuer: this._orgId,
      subject: {
        agentId: params.agentId,
        orgId: this._orgId
      },
      capabilities: Object.freeze([...(params.capabilities || [])]),
      allowedOrgs: params.allowedOrgs || ['*'],
      trustLevel: Math.min(10, Math.max(1, params.trustLevel || 5)),
      issuedAt: now,
      expiresAt: now + this._certificateTtlMs,
      serialNumber: crypto.randomBytes(8).toString('hex')
    };

    // Sign the certificate
    certificate.signature = this._signCertificate(certificate);

    this._certificates.set(certId, certificate);
    this.stats.issued++;

    // Evict if at capacity
    if (this._certificates.size > this._maxCertificates) {
      this._evictExpired();
    }

    return { ...certificate };
  }

  /**
   * Verifies a certificate's authenticity and validity.
   * @param {object} certificate
   * @returns {{ valid: boolean, reason?: string, trustLevel: number }}
   */
  verifyCertificate(certificate) {
    this.stats.verified++;

    // Check revocation
    if (this._revokedCerts.has(certificate.certId)) {
      this.stats.rejected++;
      return { valid: false, reason: 'Certificate has been revoked', trustLevel: 0 };
    }

    // Check expiry
    if (Date.now() > certificate.expiresAt) {
      this.stats.rejected++;
      return { valid: false, reason: 'Certificate has expired', trustLevel: 0 };
    }

    // Verify signature — if from our org, use our key
    if (certificate.issuer === this._orgId) {
      const expectedSig = this._signCertificate(certificate);
      try {
        const valid = crypto.timingSafeEqual(
          Buffer.from(certificate.signature, 'hex'),
          Buffer.from(expectedSig, 'hex')
        );
        if (!valid) {
          this.stats.rejected++;
          return { valid: false, reason: 'Invalid signature', trustLevel: 0 };
        }
      } catch {
        this.stats.rejected++;
        return { valid: false, reason: 'Signature verification failed', trustLevel: 0 };
      }
    } else {
      // External certificate — check if we trust the issuer
      const trustedOrg = this._trustedOrgs.get(certificate.issuer);
      if (!trustedOrg) {
        this.stats.rejected++;
        return { valid: false, reason: `Unknown issuer: ${certificate.issuer}`, trustLevel: 0 };
      }
      // Verify with trusted org's key
      const expectedSig = this._signCertificateWithKey(certificate, trustedOrg.publicKey);
      try {
        const valid = crypto.timingSafeEqual(
          Buffer.from(certificate.signature, 'hex'),
          Buffer.from(expectedSig, 'hex')
        );
        if (!valid) {
          this.stats.rejected++;
          return { valid: false, reason: 'External certificate signature invalid', trustLevel: 0 };
        }
      } catch {
        this.stats.rejected++;
        return { valid: false, reason: 'External signature verification failed', trustLevel: 0 };
      }
    }

    // Check if certificate allows interaction with our org
    const allowedOrgs = certificate.allowedOrgs || [];
    if (!allowedOrgs.includes('*') && !allowedOrgs.includes(this._orgId)) {
      this.stats.rejected++;
      return { valid: false, reason: `Certificate does not authorize interaction with ${this._orgId}`, trustLevel: 0 };
    }

    return { valid: true, trustLevel: certificate.trustLevel || 5 };
  }

  /**
   * Revokes a certificate.
   * @param {string} certId
   * @returns {boolean} True if certificate was found and revoked
   */
  revokeCertificate(certId) {
    this._revokedCerts.add(certId);
    const existed = this._certificates.delete(certId);
    if (existed) this.stats.revoked++;
    return existed;
  }

  /**
   * Registers a trusted external organization.
   * @param {string} orgId - Organization identifier
   * @param {string} publicKey - Their signing key for certificate verification
   * @param {number} [trustLevel=5] - How much we trust them (1-10)
   */
  trustOrganization(orgId, publicKey, trustLevel = 5) {
    this._trustedOrgs.set(orgId, {
      publicKey,
      trustLevel: Math.min(10, Math.max(1, trustLevel)),
      trustedAt: Date.now()
    });
  }

  /**
   * Removes trust for an organization.
   * @param {string} orgId
   */
  untrustOrganization(orgId) {
    this._trustedOrgs.delete(orgId);
  }

  /**
   * Returns trust status summary.
   * @returns {object}
   */
  getTrustReport() {
    const activeCerts = [];
    for (const [_id, cert] of this._certificates) {
      if (Date.now() <= cert.expiresAt) {
        activeCerts.push({
          certId: cert.certId,
          agentId: cert.subject.agentId,
          trustLevel: cert.trustLevel,
          expiresIn: cert.expiresAt - Date.now()
        });
      }
    }

    const trustedOrgs = [];
    for (const [orgId, info] of this._trustedOrgs) {
      trustedOrgs.push({ orgId, trustLevel: info.trustLevel, trustedAt: info.trustedAt });
    }

    return {
      orgId: this._orgId,
      stats: { ...this.stats },
      activeCertificates: activeCerts.length,
      revokedCertificates: this._revokedCerts.size,
      trustedOrganizations: trustedOrgs,
      certificates: activeCerts
    };
  }

  /** @private */
  _signCertificate(cert) {
    return this._signCertificateWithKey(cert, this._signingKey);
  }

  /** @private */
  _signCertificateWithKey(cert, key) {
    const data = `${cert.certId}:${cert.issuer}:${cert.subject.agentId}:${cert.subject.orgId}:${cert.capabilities.join(',')}:${cert.issuedAt}:${cert.expiresAt}:${cert.serialNumber}`;
    return crypto.createHmac('sha256', key).update(data).digest('hex');
  }

  /** @private */
  _evictExpired() {
    const now = Date.now();
    for (const [certId, cert] of this._certificates) {
      if (now > cert.expiresAt) {
        this._certificates.delete(certId);
      }
    }
  }
}

// =========================================================================
// Exports
// =========================================================================

module.exports = {
  AgentThreatIntelligence,
  MCPCertification,
  CrossOrgAgentTrust,
  THREAT_CATEGORIES,
  CERTIFICATION_REQUIREMENTS,
  CERTIFICATION_LEVELS
};
