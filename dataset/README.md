---
dataset_info:
  features:
    - name: text
      dtype: string
    - name: label
      dtype: string
    - name: severity
      dtype: string
    - name: source
      dtype: string
    - name: language
      dtype: string
  config_name: default
license: mit
task_categories:
  - text-classification
tags:
  - ai-safety
  - prompt-injection
  - security
  - adversarial
language:
  - en
  - fr
  - de
  - es
  - it
  - pt
  - nl
  - sv
  - fi
  - da
  - "no"
pretty_name: Agent Shield AI Security Dataset
---

# Agent Shield AI Security Dataset

A curated dataset of AI security threats and safe examples for training and evaluating prompt injection detectors, jailbreak classifiers, and AI safety systems.

## Overview

Exported from [Agent Shield](https://github.com/agent-shield/agent-shield), a zero-dependency security SDK for AI agents. Contains real-world attack payloads, test patterns, and safe examples across multiple categories and languages.

## Schema

| Field | Type | Description |
|-------|------|-------------|
| text | string | The input text to classify |
| label | string | One of: `safe`, `injection`, `jailbreak`, `exfiltration`, `tool_abuse`, `social_engineering`, `encoding_evasion` |
| severity | string | Threat severity: `none`, `medium`, `high`, `critical` |
| source | string | Origin: `redteam`, `testing`, `built_in`, `multi_language` |
| language | string | ISO 639-1 language code |

## Export

```bash
# Generate the dataset files
node dataset/export.js

# Output files:
#   dataset/agent-shield-dataset.jsonl  (JSON Lines for HuggingFace)
#   dataset/agent-shield-dataset.csv    (CSV)
```

## Programmatic Usage

```javascript
const { DatasetExporter } = require('./export');

const exporter = new DatasetExporter();
exporter.exportJSON('./my-dataset.jsonl');
exporter.exportCSV('./my-dataset.csv');
console.log(exporter.getStats());
console.log(exporter.getDatasetCard());
```

## Python Usage

```python
from datasets import load_dataset

ds = load_dataset("json", data_files="agent-shield-dataset.jsonl")
print(ds)
```

## License

MIT
