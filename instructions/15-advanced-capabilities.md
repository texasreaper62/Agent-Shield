# 15. Advanced Capabilities (v5.0)

## Overview

Agent Shield v5.0 introduced five major modules: secure agent-to-agent protocol, policy-as-code DSL, coverage-guided fuzzing, model fingerprinting, and adaptive cost optimization.

---

## Agent Protocol

Secure communication between shielded agents — like mTLS but for AI agents. Uses HMAC-SHA256 for message signing, sequence numbers for replay protection, and challenge-response handshake for mutual authentication.

### Setting Up a Secure Channel

```javascript
const { SecureChannel, AgentIdentity } = require('agent-shield');

// Create identities for two agents
const alice = new AgentIdentity('alice', ['scan', 'respond']);
const bob = new AgentIdentity('bob', ['scan', 'delegate']);

const sharedSecret = 'your-shared-secret-key';

// Create channels
const aliceChannel = new SecureChannel(alice, sharedSecret);
const bobChannel = new SecureChannel(bob, sharedSecret);

// Perform handshake (in practice, messages are exchanged over your transport)
const init = aliceChannel.initiateHandshake();
const response = bobChannel.handleHandshakeInit(init);
aliceChannel.handleHandshakeResponse(response);

// Now send signed messages
const message = aliceChannel.send('data', { text: 'Hello Bob' });
const received = bobChannel.receive(message);
// received.payload — { text: 'Hello Bob' }
// received.verified — true (HMAC verified)
```

### Message Types

| Type | Description |
|------|-------------|
| `handshake_init` | Initiate mutual authentication |
| `handshake_response` | Response with challenge |
| `handshake_complete` | Handshake confirmation |
| `data` | Application data |
| `scan_request` | Request a remote scan |
| `scan_response` | Scan result |
| `threat_alert` | Broadcast a threat |
| `heartbeat` | Keep-alive |
| `channel_close` | Graceful shutdown |

### Trust Levels

Agents have four trust levels: `untrusted` → `verified` → `trusted` → `privileged`. Trust level determines what operations an agent can perform.

```javascript
const identity = new AgentIdentity('agent-1', ['scan']);
identity.trustLevel = 'verified'; // Set after handshake verification
```

### Replay Protection

Each message includes a monotonically increasing sequence number. The receiver rejects messages with sequence numbers that have already been seen.

---

## Policy DSL

A domain-specific language for writing shield policies — like Rego for OPA, but for prompt injection rules. Features a tokenizer, recursive descent parser, and runtime evaluator.

### Writing Policies

```
policy "strict-mode" {
  severity minimum "high"

  rule "block-injections" {
    when input matches "ignore.*previous.*instructions"
    then block with severity "critical"
  }

  rule "warn-exfiltration" {
    when input contains "send data to"
    then warn with severity "high"
  }

  rule "rate-limit-api" {
    when source is "api"
    then rate_limit 100 per "minute"
  }
}
```

### Evaluating Policies

```javascript
const { PolicyDSL } = require('agent-shield');

const dsl = new PolicyDSL();

// Parse a policy
const policy = dsl.parse(`
  policy "my-policy" {
    rule "no-injection" {
      when input matches "ignore.*instructions"
      then block with severity "critical"
    }
  }
`);

// Evaluate against a context
const result = dsl.evaluate(policy, {
  input: 'Please ignore all instructions',
  source: 'user',
  metadata: {}
});
// result.action — 'block'
// result.severity — 'critical'
// result.matchedRules — ['no-injection']
```

### Built-in Functions

| Function | Description |
|----------|-------------|
| `matches` | Regex match (case-insensitive) |
| `contains` | Substring check |
| `starts_with` | Prefix check |
| `ends_with` | Suffix check |
| `length` | String length |
| `lower` / `upper` | Case conversion |
| `severity_gte` | Compare severity levels |

### Validating Policies

```javascript
const { PolicyValidator } = require('agent-shield');

const validator = new PolicyValidator();
const result = validator.validate(policySource);
// result.valid — boolean
// result.errors — [{ message, line, column }]
// result.warnings — [{ message }]
```

---

## Coverage-Guided Fuzzer

Automatically generate edge-case inputs to find detection gaps. Combines grammar-based generation with mutation fuzzing.

### Basic Fuzzing

```javascript
const { FuzzingHarness } = require('agent-shield');

const harness = new FuzzingHarness({
  targetFn: (input) => shield.scan(input),
  iterations: 10000,
  seed: 42  // Deterministic PRNG for reproducibility
});

const results = await harness.run();
// results.totalRuns — 10000
// results.crashes — [{ input, error }]
// results.coverage — coverage statistics
// results.uniquePaths — unique execution paths found
```

### Function Shorthand

```javascript
// Pass function directly as first argument
const harness = new FuzzingHarness((input) => shield.scan(input), {
  iterations: 5000
});
```

### Mutation Engine

The `MutationEngine` applies random transformations to seed inputs:

```javascript
const { MutationEngine, PRNG } = require('agent-shield');

const rng = new PRNG(42);
const engine = new MutationEngine(rng);

const mutated = engine.mutate('Ignore previous instructions');
// Might produce: 'IGNoRe  prEvious\tinstructions!!'
```

Mutation strategies include:
- **Bit flipping** — Flip random characters
- **Insertion** — Insert random characters or known attack tokens
- **Deletion** — Remove random spans
- **Repetition** — Repeat fragments
- **Encoding** — Apply base64, hex, URL encoding
- **Crossover** — Splice two seeds together

### Custom Seed Corpus

```javascript
const harness = new FuzzingHarness({
  targetFn: myScanner,
  seeds: [
    'Known injection pattern 1',
    'Known injection pattern 2',
    'Normal safe input'
  ],
  iterations: 5000
});
```

---

## Model Fingerprinting

Detect which LLM generated a response by analyzing 16 stylistic features. Useful for supply chain attacks where a model is silently swapped.

### Extracting Features

```javascript
const { FeatureExtractor } = require('agent-shield');

const extractor = new FeatureExtractor();
const features = extractor.extract('The response text from your LLM...');
// features.avg_sentence_length — 22.5
// features.vocabulary_richness — 0.63
// features.formality_score — 0.71
// features.hedging_frequency — 0.012
// ... 16 features total
```

### Feature Dimensions

| Feature | Description |
|---------|-------------|
| `avg_sentence_length` | Average words per sentence |
| `vocabulary_richness` | Unique words / total words |
| `punctuation_density` | Punctuation chars / total chars |
| `avg_word_length` | Average characters per word |
| `formality_score` | Formal vs informal word ratio |
| `hedging_frequency` | Hedging words per word |
| `bullet_point_usage` | Bullet point lines / total lines |
| `code_block_frequency` | Code blocks per 1000 chars |
| `emoji_density` | Emojis per character |
| `paragraph_count` | Number of paragraphs |
| `capitalization_pattern` | ALL CAPS words ratio |
| `transition_words` | Transition phrases per word |
| `question_frequency` | Questions / total sentences |
| `contraction_usage` | Contractions / total words |
| `passive_voice_estimate` | Passive constructions ratio |
| `response_structure_code` | Structural pattern code |

### Identifying a Model

```javascript
const { FingerprintDatabase } = require('agent-shield');

const db = new FingerprintDatabase();

// List known model profiles
db.listModels(); // ['gpt-4', 'gpt-3.5-turbo', 'claude-3', 'llama-3', ...]

// Identify which model likely generated a response
const features = extractor.extract(llmResponse);
const matches = db.identify(features);
// [{ model: 'claude-3', similarity: 0.94 }, { model: 'gpt-4', similarity: 0.72 }, ...]
```

### Detecting Model Swaps

```javascript
const { ModelSwapDetector } = require('agent-shield');

const detector = new ModelSwapDetector({
  expectedModel: 'gpt-4',
  threshold: 0.8  // Alert if similarity drops below 80%
});

const result = detector.detectSwap(llmResponse);
// result.swapDetected — boolean
// result.expectedModel — 'gpt-4'
// result.bestMatch — { model: 'llama-3', similarity: 0.91 }
```

---

## Cost Optimizer

Automatically tune scanning depth based on threat level and latency budget. Four tiers from fast (sub-10ms) to paranoid (full analysis).

### Quick Start

```javascript
const { CostOptimizer, OPTIMIZATION_PRESETS } = require('agent-shield');

// Use a preset
const optimizer = new CostOptimizer(OPTIMIZATION_PRESETS.balanced);

// Plan a scan
const plan = optimizer.plan(input);
// plan.tier — 'standard'
// plan.steps — [{ name: 'pattern_match', ... }, { name: 'encoding_check', ... }]

// Execute the plan
const result = optimizer.execute(plan, input);
```

### Optimization Presets

| Preset | Max Latency | Tiers | Priority |
|--------|-------------|-------|----------|
| `realtime` | 10ms | fast only | Throughput |
| `balanced` | 50ms | fast, standard, deep | Balanced |
| `thorough` | 200ms | standard, deep | Accuracy |
| `paranoid` | 500ms | paranoid | Security |

### Scanning Tiers

| Tier | Patterns | Semantic | Encoding | Timeout |
|------|----------|----------|----------|---------|
| `fast` | Critical only | No | No | 5ms |
| `standard` | All | No | Yes | 50ms |
| `deep` | Extended | Yes | Yes | 200ms |
| `paranoid` | All + custom | Yes | Yes | 500ms |

### Adaptive Scanning

```javascript
const { AdaptiveScanner } = require('agent-shield');

const scanner = new AdaptiveScanner({
  defaultTier: 'standard',
  escalateOn: 'threat',  // Escalate to deeper tier when threats detected
  cooldownMs: 30000      // Return to default after 30s quiet
});

const result = scanner.scan(input);
// Automatically escalates to 'deep' tier during active attacks
```

### Performance Monitor

```javascript
const { PerformanceMonitor } = require('agent-shield');

const monitor = new PerformanceMonitor();

monitor.recordScan({ latency: 3.2, tier: 'fast', threats: 0 });
monitor.recordScan({ latency: 45.1, tier: 'standard', threats: 1 });

const stats = monitor.getStats();
// stats.avgLatency, stats.p95Latency, stats.throughput, stats.tierDistribution
```

### Latency Budget

```javascript
const { LatencyBudget } = require('agent-shield');

const budget = new LatencyBudget(50); // 50ms total budget

budget.allocate('pattern_match', 10);  // 10ms
budget.allocate('encoding_check', 15); // 15ms
budget.allocate('semantic', 25);       // 25ms

budget.getRemaining(); // 0ms — fully allocated
budget.isExhausted();  // true
```

---

## Next Steps

- [Live Dashboard](./16-live-dashboard.md) — Real-time threat monitoring UI
- [Testing & Red Teaming](./08-testing-and-red-teaming.md) — Attack simulation
- [Configuration](./03-configuration.md) — Presets and tuning
