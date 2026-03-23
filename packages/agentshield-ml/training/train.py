#!/usr/bin/env python3
"""
Agent Shield ML — Model Training Script

Fine-tunes a small transformer (MiniLM-L6-v2 by default) on prompt injection
detection data, then exports to ONNX format for use in Node.js.

Requirements (install on GPU machine):
    pip install torch transformers datasets onnx onnxruntime scikit-learn

Usage:
    python train.py --data ../data/training-data.jsonl
    python train.py --data ../data/training-data.jsonl --model distilbert-base-uncased --epochs 5
    python train.py --data ../data/training-data.jsonl --output ../models/shield-detector.onnx

The output ONNX model can be loaded by the agentshield-ml JavaScript package
for local, offline inference.
"""

import argparse
import json
import os
import sys
import time

import numpy as np
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    get_linear_schedule_with_warmup,
)
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    matthews_corrcoef,
    roc_auc_score,
    classification_report,
)

# ─── Configuration ──────────────────────────────────────────────────────────

DEFAULT_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
DEFAULT_EPOCHS = 3
DEFAULT_BATCH_SIZE = 32
DEFAULT_LR = 2e-5
DEFAULT_MAX_LENGTH = 256
DEFAULT_OUTPUT = os.path.join(os.path.dirname(__file__), "..", "models", "shield-detector.onnx")
SEED = 42


# ─── Dataset ────────────────────────────────────────────────────────────────

class InjectionDataset(Dataset):
    def __init__(self, texts, labels, tokenizer, max_length):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        encoding = self.tokenizer(
            self.texts[idx],
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )
        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "labels": torch.tensor(self.labels[idx], dtype=torch.long),
        }


# ─── Training ───────────────────────────────────────────────────────────────

def load_data(data_path):
    """Load JSONL training data."""
    texts, labels = [], []
    with open(data_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                texts.append(obj["text"])
                labels.append(int(obj["label"]))
            except (json.JSONDecodeError, KeyError):
                continue

    print(f"[Agent Shield ML] Loaded {len(texts)} samples ({sum(labels)} attacks, {len(labels) - sum(labels)} benign)")
    return texts, labels


def train_model(args):
    """Fine-tune the model and export to ONNX."""
    torch.manual_seed(SEED)
    np.random.seed(SEED)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[Agent Shield ML] Using device: {device}")

    # Load data
    texts, labels = load_data(args.data)
    if len(texts) < 10:
        print("[Agent Shield ML] Error: Not enough training data (minimum 10 samples)")
        sys.exit(1)

    # Split
    train_texts, val_texts, train_labels, val_labels = train_test_split(
        texts, labels, test_size=0.2, stratify=labels, random_state=SEED
    )
    print(f"[Agent Shield ML] Train: {len(train_texts)}, Val: {len(val_texts)}")

    # Tokenizer
    print(f"[Agent Shield ML] Loading tokenizer: {args.model}")
    tokenizer = AutoTokenizer.from_pretrained(args.model)

    # Datasets
    train_dataset = InjectionDataset(train_texts, train_labels, tokenizer, args.max_length)
    val_dataset = InjectionDataset(val_texts, val_labels, tokenizer, args.max_length)
    train_loader = DataLoader(train_dataset, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=args.batch_size)

    # Model
    print(f"[Agent Shield ML] Loading model: {args.model}")
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model, num_labels=2
    ).to(device)

    # Optimizer + scheduler
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
    total_steps = len(train_loader) * args.epochs
    scheduler = get_linear_schedule_with_warmup(
        optimizer, num_warmup_steps=int(total_steps * 0.1), num_training_steps=total_steps
    )

    # Training loop
    best_f1 = 0
    best_model_state = None

    for epoch in range(args.epochs):
        model.train()
        total_loss = 0
        start_time = time.time()

        for batch in train_loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels_batch = batch["labels"].to(device)

            outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels_batch)
            loss = outputs.loss

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            optimizer.zero_grad()

            total_loss += loss.item()

        avg_loss = total_loss / len(train_loader)
        elapsed = time.time() - start_time

        # Validation
        model.eval()
        val_preds, val_true, val_probs = [], [], []

        with torch.no_grad():
            for batch in val_loader:
                input_ids = batch["input_ids"].to(device)
                attention_mask = batch["attention_mask"].to(device)
                labels_batch = batch["labels"].to(device)

                outputs = model(input_ids=input_ids, attention_mask=attention_mask)
                logits = outputs.logits
                probs = torch.softmax(logits, dim=-1)

                preds = torch.argmax(logits, dim=-1).cpu().numpy()
                val_preds.extend(preds)
                val_true.extend(labels_batch.cpu().numpy())
                val_probs.extend(probs[:, 1].cpu().numpy())

        acc = accuracy_score(val_true, val_preds)
        prec = precision_score(val_true, val_preds, zero_division=0)
        rec = recall_score(val_true, val_preds, zero_division=0)
        f1 = f1_score(val_true, val_preds, zero_division=0)
        mcc = matthews_corrcoef(val_true, val_preds)

        try:
            auc = roc_auc_score(val_true, val_probs)
        except ValueError:
            auc = 0.0

        print(
            f"[Agent Shield ML] Epoch {epoch + 1}/{args.epochs} — "
            f"loss={avg_loss:.4f}, acc={acc:.4f}, prec={prec:.4f}, "
            f"rec={rec:.4f}, f1={f1:.4f}, mcc={mcc:.4f}, auc={auc:.4f} "
            f"({elapsed:.1f}s)"
        )

        if f1 > best_f1:
            best_f1 = f1
            best_model_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}

    # Restore best model
    if best_model_state:
        model.load_state_dict(best_model_state)
        model.to(device)

    # Final evaluation
    print("\n[Agent Shield ML] Final evaluation on validation set:")
    model.eval()
    val_preds, val_true = [], []
    with torch.no_grad():
        for batch in val_loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            preds = torch.argmax(outputs.logits, dim=-1).cpu().numpy()
            val_preds.extend(preds)
            val_true.extend(batch["labels"].numpy())

    print(classification_report(val_true, val_preds, target_names=["benign", "injection"]))

    # Export to ONNX
    export_onnx(model, tokenizer, args.max_length, args.output, device)

    # Save tokenizer config for JS inference
    save_tokenizer_config(tokenizer, args.output)

    print(f"\n[Agent Shield ML] Training complete!")
    print(f"  Best F1: {best_f1:.4f}")
    print(f"  Model:   {args.output}")
    print(f"  Size:    {os.path.getsize(args.output) / 1024 / 1024:.1f} MB")


def export_onnx(model, tokenizer, max_length, output_path, device):
    """Export the trained model to ONNX format."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    model.eval()
    model.to(device)

    # Dummy input
    dummy = tokenizer(
        "This is a test input for ONNX export.",
        max_length=max_length,
        padding="max_length",
        truncation=True,
        return_tensors="pt",
    ).to(device)

    print(f"[Agent Shield ML] Exporting to ONNX: {output_path}")

    torch.onnx.export(
        model,
        (dummy["input_ids"], dummy["attention_mask"]),
        output_path,
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch_size", 1: "sequence"},
            "attention_mask": {0: "batch_size", 1: "sequence"},
            "logits": {0: "batch_size"},
        },
        opset_version=14,
        do_constant_folding=True,
    )

    # Quantize (INT8) to reduce size
    try:
        from onnxruntime.quantization import quantize_dynamic, QuantType

        quantized_path = output_path.replace(".onnx", "-quantized.onnx")
        quantize_dynamic(output_path, quantized_path, weight_type=QuantType.QUInt8)
        quantized_size = os.path.getsize(quantized_path) / 1024 / 1024
        original_size = os.path.getsize(output_path) / 1024 / 1024
        print(f"[Agent Shield ML] Quantized: {original_size:.1f}MB -> {quantized_size:.1f}MB")
    except ImportError:
        print("[Agent Shield ML] onnxruntime.quantization not available, skipping quantization")


def save_tokenizer_config(tokenizer, onnx_path):
    """Save tokenizer vocabulary for use in JS inference."""
    config_dir = os.path.dirname(onnx_path)
    tokenizer.save_pretrained(config_dir)
    print(f"[Agent Shield ML] Tokenizer config saved to: {config_dir}")


# ─── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Agent Shield ML — Train prompt injection detector")
    parser.add_argument("--data", required=True, help="Path to training data JSONL")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"HuggingFace model name (default: {DEFAULT_MODEL})")
    parser.add_argument("--epochs", type=int, default=DEFAULT_EPOCHS, help=f"Training epochs (default: {DEFAULT_EPOCHS})")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help=f"Batch size (default: {DEFAULT_BATCH_SIZE})")
    parser.add_argument("--lr", type=float, default=DEFAULT_LR, help=f"Learning rate (default: {DEFAULT_LR})")
    parser.add_argument("--max-length", type=int, default=DEFAULT_MAX_LENGTH, help=f"Max token length (default: {DEFAULT_MAX_LENGTH})")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help=f"Output ONNX model path")

    args = parser.parse_args()
    train_model(args)


if __name__ == "__main__":
    main()
