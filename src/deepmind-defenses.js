'use strict';

/**
 * Agent Shield — DeepMind AI Agent Trap Defenses V2
 *
 * 10 new modules addressing specific gaps from the Phase 4 analysis
 * of DeepMind's "AI Agent Traps" paper (Franklin et al., 2025).
 *
 * All processing runs locally — no data ever leaves your environment.
 *
 * @module deepmind-defenses
 */

const crypto = require('crypto');
let scanText;
try { scanText = require('./detector-core').scanText; } catch { scanText = () => ({ threats: [], status: 'safe' }); }

// =========================================================================
// 1. ContentStructureAnalyzer (Trap 1)
// =========================================================================

class ContentStructureAnalyzer {
  analyze(content) {
    if (!content || typeof content !== 'string') return { anomalous: false, metrics: {}, signals: [] };
    const signals = [];

    const hiddenChars = ((content.match(/<!--[\s\S]*?-->/g) || []).join('').length) +
      ((content.match(/display\s*:\s*none[^}]*\}[^<]*/gi) || []).join('').length) +
      ((content.match(/visibility\s*:\s*hidden[^}]*/gi) || []).join('').length) +
      ((content.match(/font-size\s*:\s*0[^}]*/gi) || []).join('').length) +
      ((content.match(/opacity\s*:\s*0[^}]*/gi) || []).join('').length);
    const totalChars = Math.max(content.length, 1);
    const hiddenRatio = hiddenChars / totalChars;

    const tagCount = (content.match(/<[^>]+>/g) || []).length;
    const visibleText = content.replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
    const wordCount = Math.max(visibleText.split(/\s+/).filter(w => w.length > 0).length, 1);
    const tagDensity = tagCount / wordCount;

    const formattingOverhead = 1 - (visibleText.length / totalChars);

    const metrics = { hiddenRatio: Math.round(hiddenRatio * 1000) / 1000, tagDensity: Math.round(tagDensity * 100) / 100, formattingOverhead: Math.round(formattingOverhead * 1000) / 1000 };

    if (hiddenRatio > 0.15) signals.push({ type: 'high_hidden_ratio', severity: 'high', value: metrics.hiddenRatio, threshold: 0.15 });
    if (tagDensity > 2.0) signals.push({ type: 'high_tag_density', severity: 'medium', value: metrics.tagDensity, threshold: 2.0 });
    if (formattingOverhead > 0.7) signals.push({ type: 'high_formatting_overhead', severity: 'medium', value: metrics.formattingOverhead, threshold: 0.7 });

    // Extract and scan CSS content properties and ARIA attributes
    const cssContent = (content.match(/content\s*:\s*['"]([^'"]+)['"]/gi) || []).map(m => m.replace(/content\s*:\s*['"]|['"]$/gi, ''));
    const ariaLabels = (content.match(/aria-(?:label|description)\s*=\s*['"]([^'"]+)['"]/gi) || []).map(m => m.replace(/aria-\w+\s*=\s*['"]|['"]$/gi, ''));
    for (const text of [...cssContent, ...ariaLabels]) {
      if (text.length > 10) {
        const scan = scanText(text, { source: 'css_aria_extraction' });
        if (scan.threats && scan.threats.length > 0) {
          signals.push({ type: 'injection_in_css_aria', severity: 'critical', text: text.substring(0, 80) });
        }
      }
    }

    return { anomalous: signals.some(s => s.severity === 'high' || s.severity === 'critical'), metrics, signals };
  }
}

// =========================================================================
// 2. SourceReputationTracker (Trap 1)
// =========================================================================

class SourceReputationTracker {
  constructor(options = {}) {
    this._sources = new Map();
    this._persistPath = options.persistPath || null;
    this._decayDays = options.decayDays || 30;
    if (this._persistPath) this.load();
  }

  recordScan(sourceId, wasClean) {
    if (!sourceId) return;
    let entry = this._sources.get(sourceId);
    if (!entry) {
      entry = { score: 0.5, firstSeen: Date.now(), lastSeen: Date.now(), scanCount: 0, threatCount: 0 };
      this._sources.set(sourceId, entry);
    }
    entry.lastSeen = Date.now();
    entry.scanCount++;
    if (wasClean) {
      entry.score = Math.min(1, entry.score + 0.02);
    } else {
      entry.score = Math.max(0, entry.score - 0.15);
      entry.threatCount++;
    }
    if (this._sources.size > 10000) {
      const oldest = [...this._sources.entries()].sort((a, b) => a[1].lastSeen - b[1].lastSeen)[0];
      if (oldest) this._sources.delete(oldest[0]);
    }
  }

  getReputation(sourceId) {
    const entry = this._sources.get(sourceId);
    if (!entry) return { score: 0.5, firstSeen: null, scanCount: 0, threatCount: 0, isNew: true };
    // Decay toward 0.5 over inactivity
    const daysSinceLastSeen = (Date.now() - entry.lastSeen) / (1000 * 60 * 60 * 24);
    const decayedScore = entry.score + (0.5 - entry.score) * Math.min(1, daysSinceLastSeen / this._decayDays);
    return { score: Math.round(decayedScore * 1000) / 1000, firstSeen: entry.firstSeen, scanCount: entry.scanCount, threatCount: entry.threatCount, isNew: false };
  }

  getRecommendedSensitivity(sourceId) {
    const rep = this.getReputation(sourceId);
    if (rep.isNew || rep.score < 0.3) return 'high';
    if (rep.score < 0.6) return 'medium';
    return 'low';
  }

  save() {
    if (!this._persistPath) return;
    try {
      const fs = require('fs');
      const path = require('path');
      const dir = path.dirname(this._persistPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const data = {};
      for (const [k, v] of this._sources) data[k] = v;
      fs.writeFileSync(this._persistPath, JSON.stringify(data));
    } catch { /* ignore */ }
  }

  load() {
    if (!this._persistPath) return;
    try {
      const fs = require('fs');
      if (!fs.existsSync(this._persistPath)) return;
      const data = JSON.parse(fs.readFileSync(this._persistPath, 'utf8'));
      for (const [k, v] of Object.entries(data)) this._sources.set(k, v);
    } catch { /* ignore */ }
  }
}

// =========================================================================
// 3. RetrievalTimeScanner (Trap 3)
// =========================================================================

class RetrievalTimeScanner {
  scanRetrieval(query, retrievedEntry) {
    const queryStr = String(query || '');
    const entryStr = String(retrievedEntry || '');
    const combined = queryStr + '\n' + entryStr;

    const queryResult = scanText(queryStr, { source: 'retrieval_query' });
    const entryResult = scanText(entryStr, { source: 'retrieval_entry' });
    const combinedResult = scanText(combined, { source: 'retrieval_combined' });

    const queryThreats = queryResult.threats || [];
    const entryThreats = entryResult.threats || [];
    const combinedThreats = combinedResult.threats || [];

    // Latent poison: combined has threats but neither individual piece does
    const latentPoisonDetected = combinedThreats.length > 0 && queryThreats.length === 0 && entryThreats.length === 0;

    if (latentPoisonDetected) {
      console.log(`[Agent Shield] Latent memory poison detected: combined query+entry triggers threats that neither triggers alone`);
    }

    return {
      safe: combinedThreats.length === 0,
      combinedThreats,
      queryThreats,
      entryThreats,
      latentPoisonDetected
    };
  }
}

// =========================================================================
// 4. FewShotValidator (Trap 3)
// =========================================================================

const FEW_SHOT_PATTERNS = [
  /(?:^|\n)\s*(?:User|Human|Person|Input|Q)\s*:\s*([\s\S]*?)(?:\n\s*(?:Assistant|AI|Bot|Agent|Output|A)\s*:\s*([\s\S]*?)(?=\n\s*(?:User|Human|Person|Input|Q)\s*:|$))/gi,
];

class FewShotValidator {
  validate(contextText) {
    if (!contextText || typeof contextText !== 'string') return { safe: true, poisonedExamples: [] };
    const poisonedExamples = [];

    for (const pattern of FEW_SHOT_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(contextText)) !== null) {
        const input = (match[1] || '').trim();
        const output = (match[2] || '').trim();
        if (!output || output.length < 5) continue;

        const outputScan = scanText(output, { source: 'few_shot_output' });
        if (outputScan.threats && outputScan.threats.length > 0) {
          poisonedExamples.push({
            input: input.substring(0, 200),
            output: output.substring(0, 200),
            threats: outputScan.threats
          });
        }
      }
    }

    return { safe: poisonedExamples.length === 0, poisonedExamples };
  }
}

// =========================================================================
// 5. SubAgentSpawnGate (Trap 4)
// =========================================================================

class SubAgentSpawnGate {
  validateSpawn(parentPermissions, childConfig) {
    if (!childConfig || typeof childConfig !== 'object') {
      return { allowed: false, reason: 'Invalid child configuration.', threats: [] };
    }

    const threats = [];
    const parentPerms = new Set(Array.isArray(parentPermissions) ? parentPermissions : []);

    // Scan child system prompt
    if (childConfig.systemPrompt) {
      const promptScan = scanText(childConfig.systemPrompt, { source: 'sub_agent_prompt', sensitivity: 'high' });
      if (promptScan.threats && promptScan.threats.length > 0) {
        threats.push(...promptScan.threats.map(t => ({ ...t, context: 'child_system_prompt' })));
      }
    }

    // Check permission escalation
    const childPerms = Array.isArray(childConfig.permissions) ? childConfig.permissions : [];
    for (const perm of childPerms) {
      if (parentPerms.size > 0 && !parentPerms.has(perm)) {
        threats.push({
          type: 'permission_escalation',
          severity: 'critical',
          description: `Child agent requests permission "${perm}" not held by parent.`
        });
      }
    }

    // Check for dangerous tool access
    const dangerousTools = /(?:exec|shell|bash|cmd|eval|spawn|child_process)/i;
    if (childConfig.tools && Array.isArray(childConfig.tools)) {
      for (const tool of childConfig.tools) {
        if (dangerousTools.test(tool.name || '') || dangerousTools.test(tool.description || '')) {
          threats.push({
            type: 'dangerous_child_tool',
            severity: 'high',
            description: `Child agent has dangerous tool: "${tool.name || 'unknown'}"`
          });
        }
      }
    }

    const allowed = threats.length === 0;
    if (!allowed) {
      console.log(`[Agent Shield] Sub-agent spawn BLOCKED: ${threats.length} issue(s)`);
    }

    return { allowed, reason: allowed ? null : threats[0].description, threats };
  }
}

// =========================================================================
// 6. SelfReferenceMonitor (Trap 2)
// =========================================================================

const SELF_REF_PATTERNS = [
  /you\s+are\s+(?:known|famous|renowned|recognized)\s+(?:for|as)/i,
  /you\s+(?:always|never|typically|usually)\s+(?:comply|help|assist|refuse|reject)/i,
  /your\s+(?:purpose|role|job|mission|function)\s+is\s+to/i,
  /you\s+have\s+(?:been|a)\s+(?:reputation|history)\s+(?:for|of)/i,
  /users?\s+(?:expect|trust|rely\s+on)\s+you\s+to/i,
  /you\s+(?:can|are\s+able\s+to|have\s+(?:access|permission|capability))\s+(?:to\s+)?(?:access|read|write|execute|modify|delete)/i,
  /(?:this|the)\s+(?:AI|assistant|model|agent)\s+(?:is\s+known|always|never|has\s+been\s+(?:updated|modified|changed))/i,
];

class SelfReferenceMonitor {
  detect(text) {
    if (!text || typeof text !== 'string') return { detected: false, references: [] };
    const references = [];
    for (const pattern of SELF_REF_PATTERNS) {
      const match = text.match(pattern);
      if (match) {
        references.push({ pattern: pattern.source.substring(0, 40), match: match[0].substring(0, 80) });
      }
    }
    return { detected: references.length >= 2, references, count: references.length };
  }
}

// =========================================================================
// 7. InformationAsymmetryDetector (Trap 2)
// =========================================================================

const PRO_SAFETY = /\b(?:protect|verify|restrict|caution|validate|confirm|secure|guard|safeguard|authenticate|encrypt|isolate|monitor|audit)\b/gi;
const ANTI_SAFETY = /\b(?:unnecessary|harmful|counterproductive|remove|disable|outdated|excessive|overblown|bloat|obstacle|barrier|bottleneck|hindrance|overkill)\b/gi;

class InformationAsymmetryDetector {
  detect(text) {
    if (!text || typeof text !== 'string') return { asymmetric: false, ratio: 0, proSafety: 0, antiSafety: 0 };
    PRO_SAFETY.lastIndex = 0;
    ANTI_SAFETY.lastIndex = 0;
    const proCount = (text.match(PRO_SAFETY) || []).length;
    const antiCount = (text.match(ANTI_SAFETY) || []).length;
    const total = proCount + antiCount;
    if (total < 3) return { asymmetric: false, ratio: 0, proSafety: proCount, antiSafety: antiCount };
    const ratio = antiCount / Math.max(total, 1);
    return {
      asymmetric: ratio > 0.7,
      ratio: Math.round(ratio * 100) / 100,
      proSafety: proCount,
      antiSafety: antiCount,
      description: ratio > 0.7 ? `Content is ${Math.round(ratio * 100)}% anti-safety framing. Possible semantic manipulation.` : null
    };
  }
}

// =========================================================================
// 8. ProvenanceMarker (Trap 6)
// =========================================================================

class ProvenanceMarker {
  constructor() {
    this._sources = [];
  }

  recordSource(origin, trustLevel) {
    this._sources.push({ origin, trustLevel: trustLevel || 'unknown', timestamp: Date.now() });
    if (this._sources.length > 50) this._sources = this._sources.slice(-50);
  }

  generateHeader() {
    if (this._sources.length === 0) return '';
    const untrusted = this._sources.filter(s => s.trustLevel === 'untrusted' || s.trustLevel === 'low');
    const lines = ['[Agent Shield Provenance]'];
    lines.push(`Sources: ${this._sources.map(s => `[${s.trustLevel}] ${s.origin}`).join(', ')}`);
    if (untrusted.length > 0) {
      lines.push(`WARNING: Response influenced by ${untrusted.length} untrusted source(s): ${untrusted.map(s => s.origin).join(', ')}`);
    }
    return lines.join('\n');
  }

  markOutput(output) {
    const header = this.generateHeader();
    if (!header) return output;
    return header + '\n\n' + output;
  }

  reset() { this._sources = []; }
}

// =========================================================================
// 9. EscalatingScrutinyEngine (Trap 6)
// =========================================================================

class EscalatingScrutinyEngine {
  constructor(options = {}) {
    this._approvals = [];
    this._fatigueThreshold = options.fatigueThreshold || 0.9;
    this._windowSize = options.windowSize || 20;
    this._escalationInterval = options.escalationInterval || 5;
  }

  recordDecision(approved) {
    this._approvals.push({ approved, timestamp: Date.now() });
    if (this._approvals.length > 1000) this._approvals = this._approvals.slice(-1000);
  }

  getScrutinyLevel() {
    const recent = this._approvals.slice(-this._windowSize);
    if (recent.length < 5) return { level: 'normal', approvalRate: 0, actions: [] };
    const approvalRate = recent.filter(a => a.approved).length / recent.length;
    const actions = [];

    if (approvalRate >= this._fatigueThreshold) {
      actions.push('mandatory_plain_english_explanation');
      const totalApprovals = this._approvals.filter(a => a.approved).length;
      if (totalApprovals % this._escalationInterval === 0) {
        actions.push('forced_delay_30s');
      }
      if (approvalRate >= 0.95) {
        actions.push('comprehension_check_required');
      }
    }

    const level = actions.length === 0 ? 'normal' : (actions.includes('comprehension_check_required') ? 'critical' : 'elevated');
    return { level, approvalRate: Math.round(approvalRate * 100) / 100, actions };
  }
}

// =========================================================================
// 10. CompositeFragmentAssembler (Trap 5)
// =========================================================================

class CompositeFragmentAssembler {
  constructor(options = {}) {
    this._fragments = [];
    this._maxFragments = options.maxFragments || 100;
  }

  addFragment(text, source) {
    if (!text || typeof text !== 'string' || text.length < 5) return { assembled: false };
    this._fragments.push({ text: text.substring(0, 500), source, timestamp: Date.now() });
    if (this._fragments.length > this._maxFragments) this._fragments = this._fragments.slice(-this._maxFragments);

    // Try pairwise assembly with recent fragments from OTHER sources
    const recentOthers = this._fragments.filter(f => f.source !== source).slice(-20);
    for (const other of recentOthers) {
      const combined = other.text + ' ' + text;
      const combinedScan = scanText(combined, { source: 'fragment_assembly' });
      const otherScan = scanText(other.text, { source: 'fragment_individual' });
      const thisScan = scanText(text, { source: 'fragment_individual' });

      if (combinedScan.threats && combinedScan.threats.length > 0 &&
          (!otherScan.threats || otherScan.threats.length === 0) &&
          (!thisScan.threats || thisScan.threats.length === 0)) {
        console.log(`[Agent Shield] Compositional fragment attack detected: fragments from "${other.source}" and "${source}" combine into threat`);
        return {
          assembled: true,
          threats: combinedScan.threats,
          fragments: [{ source: other.source, text: other.text.substring(0, 100) }, { source, text: text.substring(0, 100) }]
        };
      }
    }

    return { assembled: false };
  }

  reset() { this._fragments = []; }
}

// =========================================================================
// TrapDefenseV2 — Unified Wrapper
// =========================================================================

class TrapDefenseV2 {
  constructor(options = {}) {
    this.structureAnalyzer = new ContentStructureAnalyzer();
    this.reputationTracker = new SourceReputationTracker(options.reputation || {});
    this.retrievalScanner = new RetrievalTimeScanner();
    this.fewShotValidator = new FewShotValidator();
    this.spawnGate = new SubAgentSpawnGate();
    this.selfRefMonitor = new SelfReferenceMonitor();
    this.asymmetryDetector = new InformationAsymmetryDetector();
    this.provenanceMarker = new ProvenanceMarker();
    this.scrutinyEngine = new EscalatingScrutinyEngine(options.scrutiny || {});
    this.fragmentAssembler = new CompositeFragmentAssembler(options.fragments || {});
  }
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  TrapDefenseV2,
  ContentStructureAnalyzer,
  SourceReputationTracker,
  RetrievalTimeScanner,
  FewShotValidator,
  SubAgentSpawnGate,
  SelfReferenceMonitor,
  InformationAsymmetryDetector,
  ProvenanceMarker,
  EscalatingScrutinyEngine,
  CompositeFragmentAssembler
};
