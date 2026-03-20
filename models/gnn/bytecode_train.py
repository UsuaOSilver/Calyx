"""
models/gnn/bytecode_train.py

Trains CalyxGNN on synthetic CFG data derived from known exploit patterns.

Node feature vector (16 dims) — matches BytecodeGraphBuilder:
  [0]  arithmetic freq   [1]  comparison freq  [2]  memory freq
  [3]  storage freq      [4]  call_ops freq     [5]  jump_ops freq
  [6]  env_info freq     [7]  push_pop freq
  [8]  has_indirect_jump [9]  has_calldataload  [10] has_value_op
  [11] has_external_call [12] block_size_norm   [13] is_entry_block
  [14] has_selfdestruct  [15] has_sstore

Labels: 1 = exploit, 0 = benign
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import torch
import torch.nn as nn

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from models.gnn.model import CalyxGNN

CHECKPOINT_DIR = Path(__file__).resolve().parents[1] / "checkpoints"
CHECKPOINT_PATH = CHECKPOINT_DIR / "bytecode_model.pt"

SEED = 42
random.seed(SEED)
torch.manual_seed(SEED)

# ── Synthetic graph generation ────────────────────────────────────────────────

def _node(
    arith=0.1, comp=0.1, mem=0.05, stor=0.0, call=0.0, jump=0.15,
    env=0.05, push=0.3, indirect=0.0, calldataload=0.0, value_op=0.0,
    ext_call=0.0, size=0.2, entry=0.0, selfdestruct=0.0, sstore=0.0,
):
    return [arith, comp, mem, stor, call, jump, env, push,
            indirect, calldataload, value_op, ext_call, size,
            entry, selfdestruct, sstore]


def _make_exploit_graph():
    """CFG typical of an AM1/AM2 exploit: tainted calldata flows to ETH CALL."""
    n_blocks = random.randint(6, 20)
    nodes = []
    # entry — reads calldata, checks caller
    nodes.append(_node(comp=0.3, jump=0.2, env=0.2, push=0.2,
                       calldataload=1.0, value_op=1.0, entry=1.0, size=0.3))
    # dispatcher blocks
    for _ in range(random.randint(2, 5)):
        nodes.append(_node(comp=0.2, jump=0.3, push=0.3, indirect=1.0,
                           calldataload=1.0, size=0.2))
    # exploit path — external call with tainted value
    nodes.append(_node(arith=0.1, call=0.3, env=0.2, push=0.2,
                       ext_call=1.0, value_op=1.0, size=0.4))
    # optional selfdestruct path
    if random.random() < 0.3:
        nodes.append(_node(call=0.4, selfdestruct=1.0, size=0.2))
    # padding blocks
    while len(nodes) < n_blocks:
        nodes.append(_node(arith=0.15, comp=0.1, mem=0.1, push=0.35, size=0.15))

    # edges: entry→dispatcher→exploit, some back-edges
    n = len(nodes)
    edges = []
    for i in range(min(3, n - 1)):
        edges.append((i, i + 1))
    for i in range(3, n - 1):
        edges.append((i, i + 1))
        if random.random() < 0.3:
            edges.append((i, random.randint(0, i)))
    if n > 1:
        edges.append((0, n - 1))

    return nodes, edges, 1


def _make_benign_graph():
    """CFG of a straightforward ERC-20 / utility contract."""
    n_blocks = random.randint(4, 15)
    nodes = []
    nodes.append(_node(comp=0.2, jump=0.2, push=0.3, env=0.1, entry=1.0, size=0.2))
    for _ in range(random.randint(1, 4)):
        nodes.append(_node(comp=0.15, jump=0.25, push=0.35, size=0.2))
    # storage read/write (normal getter/setter)
    nodes.append(_node(stor=0.3, mem=0.2, push=0.3, sstore=1.0, size=0.3))
    while len(nodes) < n_blocks:
        nodes.append(_node(arith=0.2, mem=0.15, push=0.35, size=0.2))

    n = len(nodes)
    edges = []
    for i in range(n - 1):
        edges.append((i, i + 1))
        if random.random() < 0.2:
            edges.append((i + 1, i))  # loop back

    return nodes, edges, 0


def _make_reentrancy_graph():
    """CFG with reentrancy-style pattern (external call before state update)."""
    nodes = []
    nodes.append(_node(env=0.2, comp=0.2, jump=0.2, push=0.2,
                       calldataload=1.0, entry=1.0, size=0.3))
    nodes.append(_node(stor=0.2, mem=0.1, push=0.3, sstore=0.0, size=0.25))
    # external call BEFORE sstore (reentrancy)
    nodes.append(_node(call=0.4, ext_call=1.0, value_op=1.0, size=0.35))
    nodes.append(_node(stor=0.3, sstore=1.0, push=0.2, size=0.2))
    for _ in range(random.randint(2, 5)):
        nodes.append(_node(arith=0.15, push=0.35, size=0.15))

    n = len(nodes)
    edges = [(i, i + 1) for i in range(n - 1)]
    edges.append((2, 1))  # back-edge into pre-update block

    return nodes, edges, 1


def _make_origin_auth_graph():
    """CFG using tx.origin for auth (AM3 pattern)."""
    nodes = []
    nodes.append(_node(env=0.35, comp=0.25, jump=0.2, push=0.1,
                       value_op=1.0, entry=1.0, indirect=1.0, size=0.3))
    nodes.append(_node(comp=0.3, jump=0.3, push=0.25, indirect=1.0, size=0.2))
    nodes.append(_node(call=0.3, ext_call=1.0, env=0.2, push=0.2, size=0.35))
    for _ in range(random.randint(1, 4)):
        nodes.append(_node(arith=0.1, push=0.4, size=0.15))

    n = len(nodes)
    edges = [(i, i + 1) for i in range(n - 1)]

    return nodes, edges, 1


_GENERATORS = [
    (_make_exploit_graph,    0.30),
    (_make_benign_graph,     0.40),
    (_make_reentrancy_graph, 0.15),
    (_make_origin_auth_graph,0.15),
]


def _sample_graph():
    r = random.random()
    cumulative = 0.0
    for fn, weight in _GENERATORS:
        cumulative += weight
        if r < cumulative:
            return fn()
    return _make_benign_graph()


def build_batch(n: int):
    all_nodes, all_edges, labels = [], [], []
    node_offset = 0
    batch_idx = []

    for graph_id in range(n):
        nodes, edges, label = _sample_graph()
        all_nodes.extend(nodes)
        for src, dst in edges:
            all_edges.append((src + node_offset, dst + node_offset))
        labels.append(label)
        batch_idx.extend([graph_id] * len(nodes))
        node_offset += len(nodes)

    node_features = torch.tensor(all_nodes, dtype=torch.float32)
    edge_index = (
        torch.tensor(all_edges, dtype=torch.long).t().contiguous()
        if all_edges else torch.zeros(2, 0, dtype=torch.long)
    )
    batch = torch.tensor(batch_idx, dtype=torch.long)
    labels_t = torch.tensor(labels, dtype=torch.float32)
    return node_features, edge_index, batch, labels_t


# ── Training loop ─────────────────────────────────────────────────────────────

def train():
    EPOCHS      = 120
    BATCH_SIZE  = 64
    LR          = 1e-3
    WEIGHT_DECAY= 1e-4

    model     = CalyxGNN()
    optimizer = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=EPOCHS)
    criterion = nn.BCEWithLogitsLoss()

    print(f"Training CalyxGNN for {EPOCHS} epochs (batch={BATCH_SIZE}) ...")

    best_loss = float("inf")
    best_state = None

    for epoch in range(1, EPOCHS + 1):
        model.train()
        node_features, edge_index, batch, labels = build_batch(BATCH_SIZE)
        optimizer.zero_grad()
        logits = model(node_features, edge_index, batch)
        loss = criterion(logits, labels)
        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        scheduler.step()

        if loss.item() < best_loss:
            best_loss = loss.item()
            best_state = {k: v.clone() for k, v in model.state_dict().items()}

        if epoch % 20 == 0 or epoch == 1:
            # quick eval on fresh batch
            model.eval()
            with torch.no_grad():
                nf, ei, b, lbl = build_batch(256)
                probs = torch.sigmoid(model(nf, ei, b))
                preds = (probs >= 0.5).float()
                acc = (preds == lbl).float().mean().item()
            print(f"  epoch {epoch:3d}/{EPOCHS}  loss={loss.item():.4f}  val_acc={acc:.3f}")

    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    torch.save({"model_state_dict": best_state, "epoch": EPOCHS,
                "loss": best_loss}, CHECKPOINT_PATH)
    print(f"\nCheckpoint saved → {CHECKPOINT_PATH}")
    print(f"Best loss: {best_loss:.4f}")


if __name__ == "__main__":
    train()
