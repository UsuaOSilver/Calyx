"""
models/gnn/bytecode_train.py

Training script for the bytecode-native CalyxGNN.

Reads from data/datasets/bytecode_merged/ (real on-chain CFG graphs merged with synthetic).
Saves checkpoint to models/checkpoints/bytecode_model.pt.

Run:
    python3 -m models.gnn.bytecode_train

Or with PYTHONPATH:
    PYTHONPATH=/root/Calyx-dev python3 models/gnn/bytecode_train.py

--- IMPORTANT: pos_weight and dataset composition ---

pos_weight is computed fresh from the training split every run:

    pos_weight = n_benign / n_exploit

This upweights the minority class (typically exploit) so the model maintains high
recall for exploit detection even when benign contracts outnumber exploits.

Rule: any time the dataset composition changes (new benign sources added via
defillama_benign_collector.py, or new exploit addresses added), re-run this script.
The pos_weight adjusts automatically — do not hardcode it.

History of dataset imbalance:
  2026-03-15: synthetic only (500/500) → pos_weight=1.0  → F1=1.000 (synthetic val)
  2026-03-22: 63 benign / 1,535 exploit (24:1 exploit-heavy) → undertrained on benign
  2026-03-22: 5,882 benign / 1,535 exploit (3.8:1 benign-heavy) → pos_weight=2.32
              Fixed broken formula (was w_benign/w_exploit=0.43, which penalised
              missing exploits LESS — opposite of what a security detector needs).
"""

import json
import logging
import time
from pathlib import Path

import torch
import torch.nn as nn
from torch.optim import Adam
from torch.optim.lr_scheduler import ReduceLROnPlateau
from torch.utils.data import DataLoader

from models.gnn.model import CalyxGNN
from models.gnn.dataset import TransactionGraphDataset, collate_graphs

# ── Config ────────────────────────────────────────────────────────────────────

CHECKPOINT_DIR  = Path(__file__).resolve().parents[2] / "models" / "checkpoints"
BYTECODE_DIR    = Path(__file__).resolve().parents[2] / "data" / "datasets" / "bytecode_merged"
CHECKPOINT_PATH = CHECKPOINT_DIR / "bytecode_model.pt"

CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("calyx.bytecode_train")

CONFIG = {
    "epochs":               80,
    "batch_size":           16,      # smaller dataset
    "learning_rate":        1e-3,
    "hidden_dim":           64,
    "dropout":              0.3,
    "early_stop_patience":  15,
    "device":               "cuda" if torch.cuda.is_available() else "cpu",
}


# ── Metrics ───────────────────────────────────────────────────────────────────

def compute_metrics(logits: torch.Tensor, labels: torch.Tensor) -> dict:
    probs = torch.sigmoid(logits)
    preds = (probs >= 0.5).float()

    tp = ((preds == 1) & (labels == 1)).sum().item()
    tn = ((preds == 0) & (labels == 0)).sum().item()
    fp = ((preds == 1) & (labels == 0)).sum().item()
    fn = ((preds == 0) & (labels == 1)).sum().item()

    accuracy  = (tp + tn) / (tp + tn + fp + fn + 1e-9)
    precision = tp / (tp + fp + 1e-9)
    recall    = tp / (tp + fn + 1e-9)
    f1        = 2 * precision * recall / (precision + recall + 1e-9)

    return {"accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1}


# ── Train / eval ──────────────────────────────────────────────────────────────

def train_epoch(model, loader, optimizer, criterion, device) -> dict:
    model.train()
    total_loss = 0
    all_logits, all_labels = [], []

    for node_features, edge_index, batch, labels in loader:
        node_features = node_features.to(device)
        edge_index    = edge_index.to(device)
        batch         = batch.to(device)
        labels        = labels.to(device)

        optimizer.zero_grad()
        logits = model(node_features, edge_index, batch)
        loss   = criterion(logits, labels)
        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimizer.step()

        total_loss += loss.item()
        all_logits.append(logits.detach())
        all_labels.append(labels.detach())

    metrics = compute_metrics(torch.cat(all_logits), torch.cat(all_labels))
    metrics["loss"] = total_loss / len(loader)
    return metrics


@torch.no_grad()
def evaluate(model, loader, criterion, device) -> dict:
    model.eval()
    total_loss = 0
    all_logits, all_labels = [], []

    for node_features, edge_index, batch, labels in loader:
        node_features = node_features.to(device)
        edge_index    = edge_index.to(device)
        batch         = batch.to(device)
        labels        = labels.to(device)

        logits = model(node_features, edge_index, batch)
        loss   = criterion(logits, labels)

        total_loss += loss.item()
        all_logits.append(logits)
        all_labels.append(labels)

    metrics = compute_metrics(torch.cat(all_logits), torch.cat(all_labels))
    metrics["loss"] = total_loss / len(loader)
    return metrics


def get_dataloader(split: str, batch_size: int, shuffle: bool) -> DataLoader:
    dataset = TransactionGraphDataset(split=split, processed_dir=BYTECODE_DIR)
    return DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=shuffle,
        collate_fn=collate_graphs,
        num_workers=0,
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def train() -> float:
    device = CONFIG["device"]
    log.info(f"Bytecode GNN training on: {device}")
    log.info(f"Config: {CONFIG}")
    log.info(f"Dataset: {BYTECODE_DIR}")

    train_loader = get_dataloader("train", CONFIG["batch_size"], shuffle=True)
    val_loader   = get_dataloader("val",   CONFIG["batch_size"], shuffle=False)
    log.info(f"Train batches: {len(train_loader)} | Val batches: {len(val_loader)}")

    model = CalyxGNN(
        node_feature_dim=16,
        hidden_dim=CONFIG["hidden_dim"],
        dropout=CONFIG["dropout"],
    ).to(device)

    total_params = sum(p.numel() for p in model.parameters())
    log.info(f"Model parameters: {total_params:,}")

    # Class balance
    train_dataset = get_dataloader("train", CONFIG["batch_size"], shuffle=False).dataset
    n_benign  = sum(1 for g in train_dataset.graphs if g["label"] == 0)
    n_exploit = sum(1 for g in train_dataset.graphs if g["label"] == 1)
    # pos_weight > 1 boosts recall for the minority exploit class.
    # PyTorch BCEWithLogitsLoss multiplies the positive-class loss by pos_weight.
    pos_weight = torch.tensor([n_benign / max(n_exploit, 1)], device=device)
    log.info(f"Class balance — benign: {n_benign}, exploit: {n_exploit}, pos_weight: {pos_weight.item():.2f}")

    optimizer = Adam(model.parameters(), lr=CONFIG["learning_rate"])
    scheduler = ReduceLROnPlateau(optimizer, patience=5, factor=0.5)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    best_val_f1   = 0.0
    best_epoch    = 0
    patience_left = CONFIG["early_stop_patience"]
    history       = []

    log.info("=" * 60)
    log.info("Starting bytecode GNN training...")
    log.info(f"{'Epoch':>6} | {'Train Loss':>10} | {'Val Loss':>8} | {'Val F1':>6} | {'Val Recall':>10}")
    log.info("-" * 60)

    for epoch in range(1, CONFIG["epochs"] + 1):
        t0 = time.time()
        train_m = train_epoch(model, train_loader, optimizer, criterion, device)
        val_m   = evaluate(model, val_loader, criterion, device)
        scheduler.step(val_m["loss"])

        log.info(
            f"{epoch:>6} | {train_m['loss']:>10.4f} | {val_m['loss']:>8.4f} | "
            f"{val_m['f1']:>6.3f} | {val_m['recall']:>10.3f}  ({time.time()-t0:.1f}s)"
        )
        history.append({"epoch": epoch, "train": train_m, "val": val_m})

        if val_m["f1"] > best_val_f1:
            best_val_f1   = val_m["f1"]
            best_epoch    = epoch
            patience_left = CONFIG["early_stop_patience"]
            torch.save({
                "epoch":              epoch,
                "model_state_dict":   model.state_dict(),
                "optimizer_state_dict": optimizer.state_dict(),
                "val_f1":             best_val_f1,
                "config":             CONFIG,
                "trained_on":         "bytecode_merged",
            }, CHECKPOINT_PATH)
        else:
            patience_left -= 1
            if patience_left == 0:
                log.info(f"Early stopping at epoch {epoch} (best was epoch {best_epoch})")
                break

    (CHECKPOINT_DIR / "bytecode_history.json").write_text(json.dumps(history, indent=2))

    log.info("=" * 60)
    log.info(f"Training complete. Best val F1: {best_val_f1:.3f} at epoch {best_epoch}")
    log.info(f"Checkpoint: {CHECKPOINT_PATH}")
    return best_val_f1


if __name__ == "__main__":
    f1 = train()
    print(f"\nBytecode GNN training complete. Best Val F1: {f1:.3f}")
    if f1 >= 0.85:
        print("Target F1 >= 0.85 achieved.")
    else:
        print(f"Below target (0.85). Consider more samples or tuning.")
