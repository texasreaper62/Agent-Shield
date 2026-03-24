# Training on RunPod (B200)

## 1. Create RunPod Instance

1. Go to [runpod.io](https://runpod.io) and sign in
2. Click **Deploy** > **GPU Cloud**
3. Select **NVIDIA B200**
4. Choose template: **RunPod Pytorch 2.x**
5. Set volume size: **50 GB** (for model weights + dataset)
6. Click **Deploy**
7. Once running, click **Connect** > **Start Web Terminal** (or SSH)

## 2. Setup Commands (copy/paste into RunPod terminal)

```bash
# Clone the repo
git clone https://github.com/texasreaper62/Claude.git
cd Claude
git checkout claude/catch-up-branch-DQtEL

# Install Python dependencies
pip install -r packages/agentshield-ml/training/requirements.txt

# Verify GPU is detected
python -c "import torch; print(f'CUDA: {torch.cuda.is_available()}, GPU: {torch.cuda.get_device_name(0) if torch.cuda.is_available() else \"None\"}')"
```

## 3. Train the Model

```bash
# Default: MiniLM-L6-v2 (fastest, ~25MB model, best for production)
python packages/agentshield-ml/training/train.py \
  --data packages/agentshield-ml/training/training-data.jsonl \
  --epochs 5 \
  --batch-size 64

# Alternative: DeBERTa-v3-small (more accurate, ~140MB model)
# python packages/agentshield-ml/training/train.py \
#   --data packages/agentshield-ml/training/training-data.jsonl \
#   --model microsoft/deberta-v3-small \
#   --epochs 5 \
#   --batch-size 32
```

With B200 + ~86K samples, expect ~5-10 minutes for MiniLM, ~15-20 minutes for DeBERTa.

## 4. Get the Trained Model

After training completes, the model is saved to:
- `packages/agentshield-ml/models/shield-detector.onnx` (full)
- `packages/agentshield-ml/models/shield-detector-quantized.onnx` (INT8, smaller)
- `packages/agentshield-ml/models/` (tokenizer config files)

Push it back to the repo:

```bash
git add packages/agentshield-ml/models/
git commit -m "Add trained prompt injection detection model"
git push origin claude/catch-up-branch-DQtEL
```

## 5. Shut Down RunPod

**Important:** Stop or terminate your RunPod instance when done to avoid charges.

## Model Comparison

| Model | Size | Speed | Accuracy | Use Case |
|-------|------|-------|----------|----------|
| MiniLM-L6-v2 | ~25MB | Fast | Good | Production / Edge |
| DistilBERT | ~65MB | Medium | Better | Server-side |
| DeBERTa-v3-small | ~140MB | Slower | Best | High-security |
