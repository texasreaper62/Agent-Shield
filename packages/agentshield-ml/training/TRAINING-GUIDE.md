# Training Guide — Agent Shield ML

## Overview

This trains a small transformer model to detect prompt injection attacks.
The trained model runs locally in Node.js via ONNX Runtime — no cloud calls.

## Step-by-Step

### 1. Prepare Training Data (on your local machine)

```bash
cd packages/agentshield-ml
node training/prepare-dataset.js
```

This creates `data/training-data.jsonl` with ~100 built-in samples.
For better results, download public datasets and include them:

```bash
# Optional: Download HackAPrompt dataset
# https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset

# Optional: Download BIPIA dataset
# https://huggingface.co/datasets/MAlmasabi/Indirect-Prompt-Injection-BIPIA-GPT

node training/prepare-dataset.js path/to/hackaprompt.csv path/to/tensortrust.jsonl path/to/bipia.jsonl
```

### 2. Set Up GPU Machine (RunPod — $10-50)

1. Go to [RunPod.io](https://runpod.io)
2. Create an account
3. Add $25 credit (minimum deposit)
4. Click "Deploy" → "GPU Pods"
5. Select a template: **RunPod PyTorch 2.0**
6. Choose GPU: **RTX 3090** ($0.31/hr) or **A100** ($0.49/hr)
7. Click "Deploy"
8. Once running, click "Connect" → "Start Web Terminal"

### 3. Upload Training Data

In the RunPod terminal:
```bash
# Create working directory
mkdir -p /workspace/agentshield && cd /workspace/agentshield

# Upload your training-data.jsonl
# Option A: Use RunPod's file browser (click "Files" tab)
# Option B: Use curl to download from your machine
# Option C: Copy-paste the file content
```

### 4. Install Dependencies & Train

```bash
# Install Python packages
pip install torch transformers datasets onnx onnxruntime scikit-learn numpy

# Upload the training script (copy train.py to the machine)
# Then run:
python train.py --data training-data.jsonl --epochs 3

# For a larger model with better accuracy:
python train.py --data training-data.jsonl --model distilbert-base-uncased --epochs 5
```

Training takes:
- ~5 minutes with 100 samples on RTX 3090
- ~30 minutes with 10K samples on RTX 3090
- ~2 hours with 70K samples on A100

### 5. Download the Model

After training completes, you'll see:
```
[Agent Shield ML] Training complete!
  Best F1: 0.9700
  Model:   models/shield-detector.onnx
  Size:    24.3 MB
```

Download these files from the RunPod file browser:
- `models/shield-detector.onnx` (the model)
- `models/shield-detector-quantized.onnx` (smaller, ~12MB)
- `models/tokenizer.json` (vocabulary)
- `models/tokenizer_config.json` (config)
- `models/special_tokens_map.json` (special tokens)

### 6. Add Model to Package

Copy the downloaded files to:
```
packages/agentshield-ml/models/
├── shield-detector.onnx          (or the quantized version)
├── tokenizer.json
├── tokenizer_config.json
└── special_tokens_map.json
```

### 7. Shut Down GPU

Go back to RunPod dashboard and click "Stop" on your pod.
Total cost: $1-5 for small datasets, $10-25 for large datasets.

### 8. Test

```bash
cd packages/agentshield-ml
node test/test-ml.js
```

## Model Comparison

| Model | Size | Accuracy | Inference Time | Best For |
|-------|------|----------|---------------|----------|
| MiniLM-L6-v2 | ~25MB | Good | ~50ms | Default, balanced |
| DistilBERT | ~65MB | Better | ~100ms | Higher accuracy |
| DeBERTa-v3-small | ~45MB | Best | ~150ms | Maximum accuracy |

## Retraining

As new attack patterns emerge, retrain the model:

1. Add new samples to `data/training-data.jsonl`
2. Spin up GPU
3. Run `python train.py --data data/training-data.jsonl`
4. Download updated model
5. Publish new version of agentshield-ml

Recommended: retrain quarterly or when detection rate drops.
