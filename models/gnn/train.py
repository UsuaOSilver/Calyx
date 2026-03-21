"""
Calyx GNN — Training script

Run:
  python3 -m models.gnn.train

Checkpoints saved to: models/checkpoints/
"""

import json
import logging
import time
from pathlib import Path

import torch
import torch.nn as nn
from torch.optim import Adam
from torch.optim.lr_scheduler import ReduceLROnPlateau

from models.gnn.model   import CalyxGNN
from models.gnn.dataset import get_dataloader

# ── Config ────────────────────────────────────────────────────────────────────
CHECKPOINT_DIR = Path(__file__).resolve().parents[2] / "models" / "checkpoints"
CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("calyx.train")

CONFIG = {
    "epochs":           50,
    "batch_size":       32,
    "learning_rate":    1e-3,
    "hidden_dim":       64,
    "dropout":          0.3,
    "early_stop_patience": 10,
    "device":           "cuda" if torch.cuda.is_available() else "cpu",
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


# ── Train one epoch ───────────────────────────────────────────────────────────
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


# ── Evaluate ──────────────────────────────────────────────────────────────────
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


# ── Main training loop ────────────────────────────────────────────────────────
def train():
    device = CONFIG["device"]
    log.info(f"Training on: {device}")
    log.info(f"Config: {CONFIG}")

    # Data
    train_loader = get_dataloader("train", batch_size=CONFIG["batch_size"], shuffle=True)
    val_loader   = get_dataloader("val",   batch_size=CONFIG["batch_size"], shuffle=False)

    log.info(f"Train batches: {len(train_loader)} | Val batches: {len(val_loader)}")

    # Model
    model = CalyxGNN(
        node_feature_dim = 16,
        edge_feature_dim = 8,
        hidden_dim       = CONFIG["hidden_dim"],
        dropout          = CONFIG["dropout"],
    ).to(device)

    total_params = sum(p.numel() for p in model.parameters())
    log.info(f"Model parameters: {total_params:,}")

    # Optimizer + loss
    # Class imbalance: weight exploit class higher (500 benign / 20 exploits = 25x)
    # This prevents model from predicting all-benign and getting high accuracy
    train_dataset  = get_dataloader("train", batch_size=CONFIG["batch_size"]).dataset
    n_benign  = sum(1 for g in train_dataset.graphs if g["label"] == 0)
    n_exploit = sum(1 for g in train_dataset.graphs if g["label"] == 1)
    total = n_benign + n_exploit
    weight_benign  = total / (2 * n_benign)  if n_benign  > 0 else 1.0
    weight_exploit = total / (2 * n_exploit) if n_exploit > 0 else 1.0

    class_weights = torch.tensor([weight_benign, weight_exploit], device=device)
    pos_weight = torch.tensor([weight_benign / weight_exploit], device=device)

    log.info(f"Class weights — benign: {n_benign}, exploit: {n_exploit}, pos_weight: {pos_weight.item():.1f}")

    optimizer = Adam(model.parameters(), lr=CONFIG["learning_rate"])
    scheduler = ReduceLROnPlateau(optimizer, patience=5, factor=0.5)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    # Training loop
    best_val_f1   = 0.0
    best_epoch    = 0
    patience_left = CONFIG["early_stop_patience"]
    history       = []

    log.info("=" * 60)
    log.info("Starting training...")
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

        # Save best model
        if val_m["f1"] > best_val_f1:
            best_val_f1   = val_m["f1"]
            best_epoch    = epoch
            patience_left = CONFIG["early_stop_patience"]

            torch.save({
                "epoch":      epoch,
                "model_state_dict": model.state_dict(),
                "optimizer_state_dict": optimizer.state_dict(),
                "val_f1":     best_val_f1,
                "config":     CONFIG,
            }, CHECKPOINT_DIR / "best_model.pt")

        else:
            patience_left -= 1
            if patience_left == 0:
                log.info(f"Early stopping at epoch {epoch} (best was epoch {best_epoch})")
                break

    # Save training history
    (CHECKPOINT_DIR / "history.json").write_text(json.dumps(history, indent=2))

    log.info("=" * 60)
    log.info(f"Training complete! Best val F1: {best_val_f1:.3f} at epoch {best_epoch}")
    log.info(f"Checkpoint saved to: {CHECKPOINT_DIR / 'best_model.pt'}")

    return best_val_f1


if __name__ == "__main__":
    f1 = train()
    print(f"\n✅ Training complete!  Best Val F1: {f1:.3f}")
    if f1 >= 0.85:
        print("   🎯 Target F1 >= 0.85 achieved!")
    else:
        print(f"   ⚠️  Below target (0.85) — consider more data or tuning")
