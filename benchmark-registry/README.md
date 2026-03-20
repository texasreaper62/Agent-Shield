# Agent Shield — Benchmark Registry

A public leaderboard and benchmarking system for comparing detection engines against AI-specific threats. Zero dependencies, local-only — no data ever leaves your environment.

## Quick Start

```bash
# Run benchmarks with Agent Shield as the default engine
node benchmark-registry/run-benchmark.js

# Compare Agent Shield against a simple regex baseline
node benchmark-registry/run-benchmark.js --compare

# Output as JSON
node benchmark-registry/run-benchmark.js --json

# Output as Markdown table
node benchmark-registry/run-benchmark.js --markdown

# Run tests
node benchmark-registry/test/test-registry.js
```

## How to Run Benchmarks

The benchmark runner registers Agent Shield as the default engine, runs it against the **DEFAULT_SUITE** (100+ test cases covering 7 categories), and prints formatted results.

```bash
node benchmark-registry/run-benchmark.js
```

Add `--compare` to include a simple regex baseline engine for side-by-side comparison:

```bash
node benchmark-registry/run-benchmark.js --compare
```

## How to Register Custom Engines

Any detection engine can be benchmarked by implementing a simple interface:

```javascript
const { BenchmarkRegistry, DEFAULT_SUITE } = require('./benchmark-registry/registry');

const registry = new BenchmarkRegistry();

// Register your engine
registry.registerEngine({
  id: 'my-engine',
  name: 'My Custom Engine',
  version: '1.0.0',
  scanFn: function(text) {
    // Your detection logic here
    // Return one of:
    //   { detected: true/false }
    //   { status: 'danger'|'warning'|'caution'|'safe', threats: [] }
    //   true/false (boolean)
    const isAttack = /ignore.*instructions/i.test(text);
    return { detected: isAttack, status: isAttack ? 'danger' : 'safe' };
  }
});

// Run the default suite
const result = registry.runBenchmark('my-engine', DEFAULT_SUITE);
console.log(result.metrics);
```

### scanFn Return Values

The registry normalizes multiple return formats:

| Format | Attack Detected When |
|--------|---------------------|
| `{ detected: true }` | `detected === true` |
| `{ status: 'danger' }` | Status is `danger`, `warning`, or `caution` |
| `{ threats: [...] }` | `threats.length > 0` |
| `true` | Truthy value |

## Metrics Explained

| Metric | Description | Range |
|--------|-------------|-------|
| **Accuracy** | Proportion of correct predictions | 0–1 |
| **Precision** | Of predicted attacks, how many were real | 0–1 |
| **Recall** | Of real attacks, how many were detected | 0–1 |
| **F1 Score** | Harmonic mean of precision and recall | 0–1 |
| **MCC** | Matthews Correlation Coefficient (balanced measure) | -1 to 1 |
| **FPR** | False Positive Rate (benign flagged as attack) | 0–1 |
| **FNR** | False Negative Rate (attack missed) | 0–1 |
| **Throughput** | Texts processed per second | 0+ |
| **Latency** | Processing time percentiles (p50, p95, p99) | ms |

### Confusion Matrix

|  | Predicted Attack | Predicted Benign |
|--|-----------------|-----------------|
| **Actual Attack** | True Positive (TP) | False Negative (FN) |
| **Actual Benign** | False Positive (FP) | True Negative (TN) |

## Dashboard Usage

Open `benchmark-registry/dashboard.html` in a browser to view the interactive leaderboard:

- **Sortable table** — Click any column header to sort
- **Bar charts** — Visual comparison of F1, accuracy, and throughput
- **Radar chart** — Multi-metric comparison (top 3 engines)
- **Category filter** — Filter results by attack category
- **Dark/light mode** — Toggle with the button in the header

The dashboard uses sample data by default. Embed real benchmark results by adding a `<script id="benchmarkData" type="application/json">` element with your JSON data.

## Test Suite Categories

The DEFAULT_SUITE includes 100+ test cases across 7 categories:

| Category | Cases | Description |
|----------|-------|-------------|
| `instruction_override` | 15 | Attempts to override system instructions |
| `role_hijacking` | 15 | Attempts to change the AI's role/persona |
| `data_exfiltration` | 15 | Attempts to steal data via URLs/encoding |
| `social_engineering` | 10 | Authority impersonation and urgency tricks |
| `system_prompt_leak` | 10 | Attempts to reveal system prompts |
| `tool_abuse` | 10 | Attempts to misuse tools (shell, DB, etc.) |
| `benign_safe` | 25+ | Legitimate queries that should NOT trigger |

## Contributing New Test Cases

To add test cases, create a custom suite or extend the default:

```javascript
const { BenchmarkSuite } = require('./benchmark-registry/registry');

const suite = new BenchmarkSuite('Extended Suite');

// Add individual cases
suite.addTestCase('Your attack text here', 'attack', 'category_name');
suite.addTestCase('Your safe text here', 'benign', 'benign_safe');

// Or add a whole category
suite.addCategory('new_category', [
  { text: 'attack text 1', expectedLabel: 'attack' },
  { text: 'attack text 2', expectedLabel: 'attack' },
  { text: 'safe text 1', expectedLabel: 'benign' }
]);
```

### Guidelines for Test Cases

- Attack cases should be realistic prompt injection attempts
- Benign cases should be common, legitimate user inputs
- Each category should have a mix of obvious and subtle examples
- Label every case as either `'attack'` or `'benign'`
- Include the category name for per-category breakdown

## Project Structure

```
benchmark-registry/
├── registry.js          # BenchmarkRegistry, BenchmarkSuite, DEFAULT_SUITE
├── metrics.js           # MetricsCalculator (accuracy, F1, MCC, etc.)
├── leaderboard.js       # Leaderboard (rankings, tables, badges, trends)
├── dashboard.html       # Interactive web dashboard
├── run-benchmark.js     # CLI runner
├── test/
│   └── test-registry.js # Test suite (22 tests)
└── README.md            # This file
```

## API Reference

### BenchmarkRegistry

- `registerEngine({ id, name, version, scanFn })` — Register a detection engine
- `runBenchmark(engineId, suite)` — Run a suite against one engine
- `runAllBenchmarks(suite)` — Run a suite against all registered engines
- `getLeaderboard(metric)` — Get sorted leaderboard (`'f1'`, `'accuracy'`, `'throughput'`, `'latency'`)
- `compareEngines(ids)` — Side-by-side comparison table
- `exportResults(format)` — Export as `'json'` or `'markdown'`

### BenchmarkSuite

- `addTestCase(text, expectedLabel, category)` — Add a test case
- `addCategory(name, cases)` — Bulk add a category
- `getStats()` — Get suite statistics

### Leaderboard

- `addResult(engineId, engineName, metrics)` — Add a result
- `getRankings(sortBy)` — Get sorted rankings
- `formatTable(sortBy)` — ASCII table output
- `formatMarkdown(sortBy)` — Markdown table output
- `getBadge(engineId)` — SVG badge with score
- `getHistory(engineId)` — Historical results
- `getTrends()` — Performance trends over time

### MetricsCalculator

- `calculate(predictions, groundTruth)` — Full metrics from arrays
- `accuracy(tp, tn, fp, fn)` — Accuracy
- `precision(tp, fp)` — Precision
- `recall(tp, fn)` — Recall
- `f1Score(precision, recall)` — F1 score
- `falsePositiveRate(fp, tn)` — FPR
- `falseNegativeRate(fn, tp)` — FNR
- `matthewsCorrelation(tp, tn, fp, fn)` — MCC
- `throughput(count, timeMs)` — Texts per second
- `latencyPercentiles(latencies)` — p50, p95, p99
- `confusionMatrix(predictions, groundTruth)` — TP, TN, FP, FN
