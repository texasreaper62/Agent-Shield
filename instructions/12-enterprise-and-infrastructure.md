# 12. Enterprise & Infrastructure (v2.0–v2.1)

## Overview

Agent Shield v2.0–v2.1 added enterprise-grade features: multi-tenant isolation, role-based access control, Kubernetes operators, Terraform providers, and OpenTelemetry integration.

---

## Multi-Tenant Isolation

Run separate shield configurations per tenant with isolated threat state, stats, and policies.

```javascript
const { EnterpriseShield } = require('agent-shield');

const enterprise = new EnterpriseShield();

// Register tenants with isolated configs
enterprise.addTenant('tenant-a', {
  sensitivity: 'high',
  blocking: true,
  preset: 'high_security'
});

enterprise.addTenant('tenant-b', {
  sensitivity: 'medium',
  blocking: false,
  preset: 'chatbot'
});

// Scan within a tenant context
const result = await enterprise.scan('tenant-a', userInput);
```

Each tenant gets:
- Isolated detection stats and threat history
- Independent circuit breaker state
- Separate allowlists and policies

---

## Role-Based Access Control (RBAC)

Control who can modify shield configuration and view threat data.

```javascript
const { RBAC } = require('agent-shield');

const rbac = new RBAC();

rbac.defineRole('security-admin', {
  permissions: ['config:write', 'threats:read', 'policy:write', 'audit:read']
});

rbac.defineRole('developer', {
  permissions: ['threats:read', 'config:read']
});

rbac.defineRole('viewer', {
  permissions: ['threats:read']
});

// Check permissions
rbac.authorize('security-admin', 'config:write'); // true
rbac.authorize('developer', 'config:write');       // false
```

---

## Debug Mode

Enterprise debug mode provides detailed scan telemetry for troubleshooting.

```javascript
const shield = new AgentShield({ debug: true });

const result = await shield.scan(input);
// result.debug contains:
//   - patternMatches: which patterns fired
//   - timings: per-step latency breakdown
//   - featureVector: extracted features
//   - decisionPath: why the verdict was reached
```

---

## Kubernetes Operator

Deploy Agent Shield as a Kubernetes sidecar or operator. See the `k8s/` directory for manifests.

### Quick Deploy

```bash
# Apply the CRD and operator
kubectl apply -f k8s/crd.yaml
kubectl apply -f k8s/operator.yaml

# Create a ShieldPolicy resource
kubectl apply -f k8s/examples/strict-policy.yaml
```

### ShieldPolicy CRD

```yaml
apiVersion: agentshield.io/v1
kind: ShieldPolicy
metadata:
  name: production-shield
spec:
  sensitivity: high
  blocking: true
  preset: high_security
  replicas: 3
  resources:
    limits:
      memory: "256Mi"
      cpu: "500m"
```

The operator watches `ShieldPolicy` resources and configures shield sidecars for annotated pods.

---

## Terraform Provider

Provision shield infrastructure as code. See `terraform-provider/` for the full provider.

```hcl
resource "agentshield_policy" "production" {
  name        = "production"
  sensitivity = "high"
  blocking    = true
  preset      = "high_security"

  rule {
    name     = "block-injections"
    category = "prompt_injection"
    action   = "block"
    severity = "critical"
  }
}

resource "agentshield_tenant" "team_alpha" {
  name      = "team-alpha"
  policy_id = agentshield_policy.production.id
}
```

---

## OpenTelemetry Collector

Export shield metrics and traces via OpenTelemetry. See `otel-collector/` for the collector configuration.

```javascript
const { AgentShield, OTelExporter } = require('agent-shield');

const shield = new AgentShield({
  telemetry: {
    enabled: true,
    endpoint: 'http://localhost:4318',  // OTLP endpoint
    serviceName: 'my-agent'
  }
});
```

### Exported Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `agentshield.scans.total` | Counter | Total scans performed |
| `agentshield.threats.total` | Counter | Total threats detected |
| `agentshield.scan.latency` | Histogram | Scan latency in ms |
| `agentshield.threats.by_severity` | Counter | Threats by severity level |
| `agentshield.circuit_breaker.state` | Gauge | Circuit breaker state |

---

## Compliance Reporting

Generate compliance reports for regulatory frameworks.

```javascript
const { ComplianceReporter } = require('agent-shield');

const reporter = new ComplianceReporter(shield);

// Generate SOC2 compliance report
const soc2 = reporter.generate('SOC2');

// Supported frameworks
const frameworks = ['SOC2', 'OWASP', 'NIST', 'EU_AI_Act', 'HIPAA', 'GDPR'];
```

Reports include:
- Control mapping (shield features → compliance controls)
- Audit trail summary
- Threat detection statistics
- Configuration assessment

---

## VS Code Extension

The `vscode-extension/` provides real-time shield monitoring in your IDE.

### Features

- Inline threat annotations in code
- Shield status in the status bar
- Threat log panel
- Quick-fix suggestions for detected issues
- Configuration snippets

### Install

```bash
cd vscode-extension
npm install && npm run compile
# Then install the .vsix file in VS Code
```

---

## Next Steps

- [Autonomous Defense](./13-autonomous-defense.md) — Self-healing, threat intelligence
- [Production Deployment](./09-production-deployment.md) — Logging, webhooks, performance tuning
