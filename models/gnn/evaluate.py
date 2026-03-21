"""
Calyx GNN — Evaluation script
Tests best_model.pt on the held-out test set

Run:
  python3 -m models.gnn.evaluate
"""

import json
import logging
from pathlib import Path

import torch

from models.gnn.model   import CalyxGNN
from models.gnn.dataset import get_dataloader
from models.gnn.train   import compute_metrics, evaluate, CONFIG

CHECKPOINT_DIR = Path(__file__).resolve().parents[2] / "models" / "checkpoints"
log = logging.getLogger("calyx.evaluate")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def load_best_model(device: str) -> CalyxGNN:
    ckpt_path = CHECKPOINT_DIR / "best_model.pt"
    if not ckpt_path.exists():
        raise FileNotFoundError(
            f"No checkpoint at {ckpt_path}\n"
            f"Train the model first:  python3 -m models.gnn.train"
        )
    ckpt = torch.load(ckpt_path, map_location=device)
    model = CalyxGNN(
        node_feature_dim = 16,
        hidden_dim       = ckpt["config"]["hidden_dim"],
        dropout          = 0.0,   # No dropout at eval time
    ).to(device)
    model.load_state_dict(ckpt["model_state_dict"])
    model.eval()
    log.info(f"Loaded model from epoch {ckpt['epoch']}  (val F1={ckpt['val_f1']:.3f})")
    return model


@torch.no_grad()
def full_evaluation():
    device      = CONFIG["device"]
    model       = load_best_model(device)
    criterion   = torch.nn.BCEWithLogitsLoss()
    test_loader = get_dataloader("test", batch_size=64, shuffle=False)

    metrics = evaluate(model, test_loader, criterion, device)

    # Print report
    print()
    print("=" * 50)
    print("  CALYX GNN — TEST SET RESULTS")
    print("=" * 50)
    print(f"  Accuracy  : {metrics['accuracy']:.3f}  (target: >0.90)")
    print(f"  Precision : {metrics['precision']:.3f}")
    print(f"  Recall    : {metrics['recall']:.3f}  (target: >0.90)")
    print(f"  F1 Score  : {metrics['f1']:.3f}  (target: >0.85)")
    print(f"  Test Loss : {metrics['loss']:.4f}")
    print("=" * 50)

    # Pass / fail against capstone targets
    targets = {
        "Accuracy  >= 0.90": metrics["accuracy"]  >= 0.90,
        "Recall    >= 0.90": metrics["recall"]    >= 0.90,
        "F1 Score  >= 0.85": metrics["f1"]        >= 0.85,
    }
    print()
    for label, passed in targets.items():
        icon = "✅" if passed else "❌"
        print(f"  {icon}  {label}")

    all_pass = all(targets.values())
    print()
    if all_pass:
        print("  🎯 All capstone targets met! Ready for midterm report.")
    else:
        print("  ⚠️  Some targets not met — consider more training data or epochs.")

    # Save results
    results = {"metrics": metrics, "targets": {k: bool(v) for k, v in targets.items()}}
    out = CHECKPOINT_DIR / "test_results.json"
    out.write_text(json.dumps(results, indent=2))
    log.info(f"Results saved to {out}")

    return metrics


if __name__ == "__main__":
    full_evaluation()
