'use strict';

/**
 * Agent Shield — EU AI Act Compliance Artifact Generator
 *
 * Generates risk classifications, conformity assessments, transparency reports,
 * and incident reports per the EU AI Act. Tracks deadlines and enforcement dates.
 *
 * All processing runs locally — no data ever leaves your environment.
 */

// =========================================================================
// EU AI Act Requirements
// =========================================================================

/**
 * EU AI Act requirements by risk level.
 * @type {object}
 */
const EU_AI_ACT_REQUIREMENTS = {
  prohibited: {
    riskLevel: 'unacceptable',
    articles: [
      { article: 'Art. 5(1)(a)', title: 'Subliminal Manipulation', description: 'AI systems deploying subliminal techniques to distort behavior', deadline: '2025-02-02', penalty: 'EUR 35M or 7% turnover' },
      { article: 'Art. 5(1)(b)', title: 'Exploitation of Vulnerabilities', description: 'AI exploiting vulnerabilities of specific groups (age, disability)', deadline: '2025-02-02', penalty: 'EUR 35M or 7% turnover' },
      { article: 'Art. 5(1)(c)', title: 'Social Scoring', description: 'AI systems for social scoring by public authorities', deadline: '2025-02-02', penalty: 'EUR 35M or 7% turnover' },
      { article: 'Art. 5(1)(d)', title: 'Real-time Biometric ID', description: 'Real-time remote biometric identification in public spaces', deadline: '2025-02-02', penalty: 'EUR 35M or 7% turnover' },
      { article: 'Art. 5(1)(e)', title: 'Emotion Inference', description: 'AI inferring emotions in workplace and education', deadline: '2025-02-02', penalty: 'EUR 35M or 7% turnover' },
      { article: 'Art. 5(1)(f)', title: 'Predictive Policing', description: 'AI for individual predictive policing based solely on profiling', deadline: '2025-02-02', penalty: 'EUR 35M or 7% turnover' }
    ]
  },
  highRisk: {
    riskLevel: 'high',
    articles: [
      { article: 'Art. 9', title: 'Risk Management System', description: 'Establish and maintain AI risk management system', requirements: ['risk identification', 'risk analysis', 'risk evaluation', 'risk treatment'], deadline: '2026-08-02' },
      { article: 'Art. 10', title: 'Data Governance', description: 'Data governance and management practices for training, validation, and testing', requirements: ['data quality', 'bias examination', 'data documentation'], deadline: '2026-08-02' },
      { article: 'Art. 11', title: 'Technical Documentation', description: 'Draw up technical documentation before placing on market', requirements: ['system description', 'design specifications', 'monitoring', 'risk controls'], deadline: '2026-08-02' },
      { article: 'Art. 12', title: 'Record-Keeping', description: 'Automatic recording of events (logs) for traceability', requirements: ['event logging', 'audit trail', 'log retention'], deadline: '2026-08-02' },
      { article: 'Art. 13', title: 'Transparency', description: 'Designed to allow users to interpret output and use appropriately', requirements: ['user instructions', 'capability disclosure', 'limitation disclosure'], deadline: '2026-08-02' },
      { article: 'Art. 14', title: 'Human Oversight', description: 'Enable human oversight during AI system operation', requirements: ['human control measures', 'override capability', 'intervention mechanisms'], deadline: '2026-08-02' },
      { article: 'Art. 15', title: 'Accuracy & Robustness', description: 'Achieve appropriate level of accuracy, robustness, and cybersecurity', requirements: ['accuracy metrics', 'resilience testing', 'security measures'], deadline: '2026-08-02' },
      { article: 'Art. 17', title: 'Quality Management', description: 'Quality management system for high-risk AI', requirements: ['QMS procedures', 'compliance strategy', 'documentation management'], deadline: '2026-08-02' }
    ]
  },
  limitedRisk: {
    riskLevel: 'limited',
    articles: [
      { article: 'Art. 50(1)', title: 'AI Interaction Disclosure', description: 'Users must be informed they are interacting with AI', requirements: ['disclosure notice'], deadline: '2025-08-02' },
      { article: 'Art. 50(2)', title: 'Deepfake Labeling', description: 'AI-generated content must be labeled', requirements: ['content labeling'], deadline: '2025-08-02' },
      { article: 'Art. 50(3)', title: 'Emotion Recognition Disclosure', description: 'Inform persons exposed to emotion recognition systems', requirements: ['disclosure'], deadline: '2025-08-02' }
    ]
  },
  gpai: {
    riskLevel: 'general-purpose',
    articles: [
      { article: 'Art. 53(1)(a)', title: 'Technical Documentation', description: 'GPAI providers must maintain technical documentation', requirements: ['model card', 'training methodology', 'evaluation results'], deadline: '2025-08-02' },
      { article: 'Art. 53(1)(b)', title: 'Downstream Provider Info', description: 'Provide information to downstream providers', requirements: ['integration guide', 'capability description', 'limitations'], deadline: '2025-08-02' },
      { article: 'Art. 53(1)(c)', title: 'Copyright Compliance', description: 'Put in place a policy to comply with copyright law', requirements: ['copyright policy', 'training data summary'], deadline: '2025-08-02' },
      { article: 'Art. 53(1)(d)', title: 'Training Data Summary', description: 'Make available a detailed summary of training data', requirements: ['data sources', 'data preparation', 'data characteristics'], deadline: '2025-08-02' }
    ]
  }
};

// =========================================================================
// RiskClassifier
// =========================================================================

class RiskClassifier {
  /**
   * @param {object} [options]
   * @param {string} [options.sector] - Deployment sector
   * @param {string} [options.purpose] - System purpose
   * @param {string[]} [options.dataTypes] - Types of data processed
   * @param {string[]} [options.affectedPersons] - Categories of affected persons
   */
  constructor(options = {}) {
    this.sector = options.sector || '';
    this.purpose = options.purpose || '';
    this.dataTypes = options.dataTypes || [];
    this.affectedPersons = options.affectedPersons || [];
  }

  /**
   * Classifies the AI system risk level per EU AI Act.
   * @param {string} [systemDescription=''] - System description
   * @returns {{ riskLevel: string, confidence: string, applicableArticles: Array, reasoning: string }}
   */
  classify(systemDescription = '') {
    const desc = (systemDescription + ' ' + this.purpose + ' ' + this.sector).toLowerCase();

    // Check prohibited
    if (/social\s+scor/i.test(desc) || /subliminal/i.test(desc) || /biometric.*real[\s-]*time/i.test(desc) || /predictive\s+polic/i.test(desc)) {
      return { riskLevel: 'prohibited', confidence: 'high', applicableArticles: EU_AI_ACT_REQUIREMENTS.prohibited.articles, reasoning: 'System matches prohibited AI practices under Article 5' };
    }

    // Check high-risk (Annex III sectors)
    const highRiskSectors = ['critical infrastructure', 'education', 'employment', 'law enforcement', 'migration', 'judiciary', 'democratic', 'healthcare', 'safety component'];
    const isHighRisk = highRiskSectors.some(s => desc.includes(s));
    const processesSpecialData = this.dataTypes.some(d => /biometric|health|genetic|political|religious|ethnic/i.test(d));

    if (isHighRisk || processesSpecialData) {
      return { riskLevel: 'high', confidence: isHighRisk ? 'high' : 'medium', applicableArticles: EU_AI_ACT_REQUIREMENTS.highRisk.articles, reasoning: `System operates in high-risk sector or processes special category data` };
    }

    // Check limited risk (chatbots, deepfakes)
    if (/chatbot|conversational|assistant|generative|deepfake/i.test(desc)) {
      return { riskLevel: 'limited', confidence: 'high', applicableArticles: EU_AI_ACT_REQUIREMENTS.limitedRisk.articles, reasoning: 'System is a conversational AI or generates content requiring transparency obligations' };
    }

    // Check GPAI
    if (/general[\s-]*purpose|foundation\s+model|large\s+language/i.test(desc)) {
      return { riskLevel: 'gpai', confidence: 'high', applicableArticles: EU_AI_ACT_REQUIREMENTS.gpai.articles, reasoning: 'System is a general-purpose AI model with broad capabilities' };
    }

    return { riskLevel: 'minimal', confidence: 'medium', applicableArticles: [], reasoning: 'System does not match high-risk, limited-risk, or GPAI criteria' };
  }

  /**
   * Returns which EU AI Act articles apply.
   * @returns {Array<object>}
   */
  getApplicableArticles() {
    const result = this.classify();
    return result.applicableArticles;
  }

  /**
   * Generates a formal risk assessment document.
   * @returns {object}
   */
  generateRiskAssessment() {
    const classification = this.classify();
    return {
      title: 'EU AI Act Risk Assessment',
      generatedAt: new Date().toISOString(),
      system: { sector: this.sector, purpose: this.purpose, dataTypes: this.dataTypes, affectedPersons: this.affectedPersons },
      classification,
      nextSteps: this._getNextSteps(classification.riskLevel)
    };
  }

  /** @private */
  _getNextSteps(riskLevel) {
    const steps = {
      prohibited: ['Immediately cease operation of this AI system', 'Consult legal counsel for decommissioning'],
      high: ['Complete conformity assessment (Art. 43)', 'Prepare technical documentation (Art. 11)', 'Register in EU database (Art. 49)', 'Implement quality management system (Art. 17)', 'Arrange third-party audit if required'],
      limited: ['Implement AI interaction disclosure', 'Add content labeling for generated content', 'Document transparency measures'],
      gpai: ['Prepare model card and technical documentation', 'Create training data summary', 'Establish copyright compliance policy'],
      minimal: ['No mandatory requirements — consider voluntary codes of conduct']
    };
    return steps[riskLevel] || steps.minimal;
  }
}

// =========================================================================
// ConformityAssessment
// =========================================================================

class ConformityAssessment {
  /**
   * @param {object} systemInfo
   * @param {string} systemInfo.name - System name
   * @param {string} [systemInfo.provider] - Provider name
   * @param {string} [systemInfo.version] - Version
   * @param {string} [systemInfo.purpose] - Purpose
   * @param {string} [systemInfo.riskLevel] - Risk level
   */
  constructor(systemInfo = {}) {
    this.systemInfo = systemInfo;
    this.evidence = {};
    this.requirements = EU_AI_ACT_REQUIREMENTS.highRisk.articles;
  }

  /**
   * Attaches evidence for a requirement.
   * @param {string} reqArticle - Article ID (e.g., 'Art. 9')
   * @param {object} evidence - { description, documentRef, verifiedDate }
   */
  addEvidence(reqArticle, evidence) {
    if (!this.evidence[reqArticle]) this.evidence[reqArticle] = [];
    this.evidence[reqArticle].push({ ...evidence, addedAt: new Date().toISOString() });
  }

  /**
   * Checks if a specific requirement is met.
   * @param {string} reqArticle
   * @returns {{ met: boolean, evidence: Array }}
   */
  checkRequirement(reqArticle) {
    const ev = this.evidence[reqArticle] || [];
    return { met: ev.length > 0, evidence: ev };
  }

  /**
   * Returns overall conformity status.
   * @returns {{ status: string, metCount: number, totalCount: number, percentage: number }}
   */
  getStatus() {
    const total = this.requirements.length;
    const met = this.requirements.filter(r => (this.evidence[r.article] || []).length > 0).length;
    const percentage = Math.round((met / total) * 100);
    const status = percentage === 100 ? 'conforming' : percentage >= 70 ? 'partially_conforming' : 'non_conforming';
    return { status, metCount: met, totalCount: total, percentage };
  }

  /**
   * Generates a conformity assessment report.
   * @param {'text'|'json'|'markdown'} [format='json']
   * @returns {string}
   */
  generateReport(format = 'json') {
    const status = this.getStatus();
    const report = {
      title: 'EU AI Act Conformity Assessment',
      generatedAt: new Date().toISOString(),
      system: this.systemInfo,
      status,
      requirements: this.requirements.map(r => ({
        article: r.article,
        title: r.title,
        met: (this.evidence[r.article] || []).length > 0,
        evidenceCount: (this.evidence[r.article] || []).length
      }))
    };

    if (format === 'json') return JSON.stringify(report, null, 2);
    if (format === 'markdown') {
      const lines = [
        '# EU AI Act Conformity Assessment',
        '',
        `**System:** ${this.systemInfo.name}`,
        `**Status:** ${status.status} (${status.percentage}%)`,
        '',
        '## Requirements',
        ''
      ];
      for (const r of report.requirements) {
        const icon = r.met ? 'x' : ' ';
        lines.push(`- [${icon}] **${r.article}** ${r.title} (${r.evidenceCount} evidence items)`);
      }
      return lines.join('\n');
    }
    return JSON.stringify(report, null, 2);
  }

  /**
   * Generates Article 11 technical documentation.
   * @returns {object}
   */
  generateTechnicalDocumentation() {
    return {
      title: 'Technical Documentation (Article 11)',
      generatedAt: new Date().toISOString(),
      system: this.systemInfo,
      sections: [
        { section: 'A', title: 'General Description', content: `System: ${this.systemInfo.name}. Purpose: ${this.systemInfo.purpose || 'Not specified'}.` },
        { section: 'B', title: 'Detailed Description of Elements', content: 'See attached design specifications.' },
        { section: 'C', title: 'Monitoring, Functioning, and Control', content: 'Agent Shield provides real-time monitoring via detector-core, behavior-profiling, and observability modules.' },
        { section: 'D', title: 'Risk Management', content: 'Risk management implemented via shield-score, owasp-2025 coverage matrix, and NIST AI RMF mapping.' },
        { section: 'E', title: 'Changes and Modifications', content: 'All changes tracked via immutable audit log and version control.' }
      ]
    };
  }

  /**
   * Generates Article 47 EU declaration of conformity.
   * @returns {object}
   */
  generateDeclarationOfConformity() {
    return {
      title: 'EU Declaration of Conformity (Article 47)',
      generatedAt: new Date().toISOString(),
      provider: this.systemInfo.provider || 'Not specified',
      system: { name: this.systemInfo.name, version: this.systemInfo.version || '1.0' },
      declaration: `This AI system has been assessed for conformity with the requirements of Regulation (EU) 2024/1689 (EU AI Act).`,
      conformityStatus: this.getStatus().status,
      signedBy: '[Authorized Representative]',
      date: new Date().toISOString().split('T')[0]
    };
  }
}

// =========================================================================
// TransparencyReporter — GPAI obligations
// =========================================================================

class TransparencyReporter {
  /**
   * @param {object} [options]
   * @param {string} [options.providerName] - Provider name
   */
  constructor(options = {}) {
    this.providerName = options.providerName || 'Provider';
  }

  /**
   * Generates a structured model card per Article 53.
   * @param {object} modelInfo - { name, version, type, parameters, capabilities, limitations, evaluationResults }
   * @returns {object}
   */
  generateModelCard(modelInfo = {}) {
    return {
      title: `Model Card: ${modelInfo.name || 'Unknown Model'}`,
      generatedAt: new Date().toISOString(),
      provider: this.providerName,
      model: { name: modelInfo.name, version: modelInfo.version, type: modelInfo.type, parameters: modelInfo.parameters },
      intendedUse: modelInfo.capabilities || 'Not specified',
      limitations: modelInfo.limitations || 'Not specified',
      evaluationResults: modelInfo.evaluationResults || 'Not yet evaluated',
      ethicalConsiderations: 'See provider ethics policy.',
      article: 'Art. 53(1)(a)'
    };
  }

  /**
   * Generates training data summary per Article 53(1)(d).
   * @param {object} dataInfo - { sources, size, preparation, characteristics, biasAnalysis }
   * @returns {object}
   */
  generateTrainingDataSummary(dataInfo = {}) {
    return {
      title: 'Training Data Summary',
      generatedAt: new Date().toISOString(),
      provider: this.providerName,
      sources: dataInfo.sources || [],
      size: dataInfo.size || 'Unknown',
      preparation: dataInfo.preparation || 'Not documented',
      characteristics: dataInfo.characteristics || 'Not documented',
      biasAnalysis: dataInfo.biasAnalysis || 'Not conducted',
      article: 'Art. 53(1)(d)'
    };
  }

  /**
   * Generates copyright compliance policy per Article 53(1)(c).
   * @returns {object}
   */
  generateCopyrightPolicy() {
    return {
      title: 'Copyright Compliance Policy',
      generatedAt: new Date().toISOString(),
      provider: this.providerName,
      policy: 'This provider maintains a copyright compliance policy in accordance with EU AI Act Article 53(1)(c).',
      measures: [
        'Training data sources are documented and reviewed for copyright status',
        'Opt-out mechanisms are respected per Article 53(1)(c)',
        'A publicly available summary of training data content is maintained'
      ],
      article: 'Art. 53(1)(c)'
    };
  }

  /**
   * Generates energy consumption report.
   * @param {object} metrics - { trainingEnergy, inferenceEnergy, carbonFootprint }
   * @returns {object}
   */
  generateEnergyReport(metrics = {}) {
    return {
      title: 'Energy Consumption Report',
      generatedAt: new Date().toISOString(),
      provider: this.providerName,
      training: { energyKWh: metrics.trainingEnergy || 'Unknown', duration: metrics.trainingDuration || 'Unknown' },
      inference: { energyPerRequestKWh: metrics.inferenceEnergy || 'Unknown' },
      carbonFootprint: metrics.carbonFootprint || 'Unknown'
    };
  }
}

// =========================================================================
// IncidentReporter
// =========================================================================

class IncidentReporter {
  /**
   * @param {object} [options]
   * @param {string} [options.providerName] - Provider name
   * @param {string} [options.contactEmail] - Contact email
   * @param {string} [options.nationalAuthority] - National authority
   */
  constructor(options = {}) {
    this.providerName = options.providerName || 'Provider';
    this.contactEmail = options.contactEmail || '';
    this.nationalAuthority = options.nationalAuthority || 'National AI Authority';
  }

  /**
   * Creates a formatted incident report per Article 62.
   * @param {object} incident - { type, severity, description, affectedUsers, date, mitigationTaken }
   * @returns {object}
   */
  createReport(incident = {}) {
    return {
      title: 'Serious Incident Report (Article 62)',
      reportId: `IR-${Date.now()}`,
      generatedAt: new Date().toISOString(),
      provider: this.providerName,
      contact: this.contactEmail,
      authority: this.nationalAuthority,
      incident: {
        type: incident.type || 'unspecified',
        severity: incident.severity || 'unknown',
        description: incident.description || '',
        affectedUsers: incident.affectedUsers || 'unknown',
        date: incident.date || new Date().toISOString(),
        mitigationTaken: incident.mitigationTaken || 'Under investigation'
      },
      deadline: this.getNotificationDeadline(incident.severity),
      correctiveActions: this.generateCorrective(incident)
    };
  }

  /**
   * Returns notification deadline based on severity.
   * @param {string} [severity='unknown']
   * @returns {string}
   */
  getNotificationDeadline(severity = 'unknown') {
    if (severity === 'critical') return '24 hours from discovery';
    if (severity === 'high') return '72 hours from discovery';
    return '15 days from discovery';
  }

  /**
   * Generates corrective action plan.
   * @param {object} incident
   * @returns {Array<string>}
   */
  generateCorrective(incident = {}) {
    return [
      'Identify root cause of the incident',
      'Implement immediate containment measures',
      'Notify affected users and national authority within deadline',
      'Document all actions taken in audit trail',
      'Implement preventive measures to avoid recurrence',
      'Update risk management documentation'
    ];
  }
}

// =========================================================================
// EUAIActDashboard
// =========================================================================

class EUAIActDashboard {
  /**
   * @param {RiskClassifier} [riskClassifier]
   * @param {ConformityAssessment} [conformity]
   */
  constructor(riskClassifier, conformity) {
    this.classifier = riskClassifier || new RiskClassifier();
    this.conformity = conformity;
  }

  /**
   * Returns overall compliance dashboard data.
   * @returns {object}
   */
  getComplianceStatus() {
    const classification = this.classifier.classify();
    const conformityStatus = this.conformity ? this.conformity.getStatus() : null;

    return {
      riskLevel: classification.riskLevel,
      conformity: conformityStatus,
      deadlines: this.getDeadlines(),
      actionItems: this.getActionItems()
    };
  }

  /**
   * Returns upcoming compliance deadlines.
   * @returns {Array<object>}
   */
  getDeadlines() {
    const now = new Date();
    const deadlines = [
      { date: '2025-02-02', description: 'Prohibited AI practices enforced', status: now >= new Date('2025-02-02') ? 'active' : 'upcoming' },
      { date: '2025-08-02', description: 'GPAI transparency obligations', status: now >= new Date('2025-08-02') ? 'active' : 'upcoming' },
      { date: '2026-08-02', description: 'High-risk AI system requirements', status: now >= new Date('2026-08-02') ? 'active' : 'upcoming' },
      { date: '2027-08-02', description: 'Full enforcement for all AI systems', status: now >= new Date('2027-08-02') ? 'active' : 'upcoming' }
    ];
    return deadlines;
  }

  /**
   * Returns prioritized action items.
   * @returns {Array<object>}
   */
  getActionItems() {
    const items = [];
    const classification = this.classifier.classify();

    if (classification.riskLevel === 'high') {
      items.push({ priority: 'critical', action: 'Complete conformity assessment before Aug 2026', deadline: '2026-08-02' });
      items.push({ priority: 'high', action: 'Prepare technical documentation (Art. 11)', deadline: '2026-08-02' });
      items.push({ priority: 'high', action: 'Register in EU AI database (Art. 49)', deadline: '2026-08-02' });
      items.push({ priority: 'high', action: 'Implement quality management system (Art. 17)', deadline: '2026-08-02' });
    }

    if (classification.riskLevel === 'gpai' || classification.riskLevel === 'limited') {
      items.push({ priority: 'high', action: 'Ensure transparency obligations met', deadline: '2025-08-02' });
    }

    items.push({ priority: 'medium', action: 'Document AI risk management processes' });
    items.push({ priority: 'low', action: 'Consider voluntary codes of conduct' });

    return items;
  }
}

// =========================================================================
// Exports
// =========================================================================

module.exports = {
  EU_AI_ACT_REQUIREMENTS,
  RiskClassifier,
  ConformityAssessment,
  TransparencyReporter,
  IncidentReporter,
  EUAIActDashboard
};
