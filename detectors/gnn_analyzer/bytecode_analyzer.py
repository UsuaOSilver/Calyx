"""
detectors/gnn_analyzer/bytecode_analyzer.py

GNN analyzer for closed-source (bytecode-only) contracts.

Loads the bytecode-trained CalyxGNN checkpoint (bytecode_model.pt) and
runs inference on a bytecode hex string by first converting it to a CFG
graph via BytecodeGraphBuilder.

Usage:
    from detectors.gnn_analyzer.bytecode_analyzer import BytecodeGNNAnalyzer

    analyzer = BytecodeGNNAnalyzer()
    result   = analyzer.analyze("0x6080604052...")
    # result["exploit_probability"]  → float [0, 1]
    # result["risk_level"]           → "HIGH" | "MEDIUM" | "LOW"
    # result["block_count"]          → int
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

import torch

from models.gnn.model import CalyxGNN
from models.gnn.bytecode_graph_builder import BytecodeGraphBuilder

DEFAULT_CHECKPOINT = (
    Path(__file__).resolve().parents[2] / "models" / "checkpoints" / "bytecode_model.pt"
)


class BytecodeGNNAnalyzer:
    """
    GNN inference wrapper for bytecode-derived CFG graphs.

    Falls back gracefully if the checkpoint is missing — returns a neutral
    0.5 probability so the rest of the pipeline can still produce a risk score.
    """

    def __init__(self, checkpoint_path: Union[str, Path] = DEFAULT_CHECKPOINT):
        self._builder   = BytecodeGraphBuilder()
        self._available = False
        self.model      = CalyxGNN()

        cp = Path(checkpoint_path)
        if not cp.exists():
            import warnings
            warnings.warn(
                f"BytecodeGNNAnalyzer: checkpoint not found at {cp}. "
                "Run models/gnn/bytecode_train.py to generate it. "
                "Returning neutral 0.5 probability until then."
            )
            return

        checkpoint = torch.load(cp, map_location="cpu", weights_only=False)
        self.model.load_state_dict(checkpoint["model_state_dict"])
        self.model.eval()
        self._available = True

    def analyze(self, bytecode_hex: str) -> dict:
        """
        Convert bytecode to a CFG graph and run GNN inference.

        Returns:
            {
                "exploit_probability": float,
                "risk_level":          "HIGH" | "MEDIUM" | "LOW",
                "block_count":         int,
                "edge_count":          int,
                "available":           bool,   # False if checkpoint missing
            }
        """
        graph = self._builder.build_graph(bytecode_hex)
        block_count = graph["num_nodes"]
        edge_count  = graph["num_edges"]

        if not self._available:
            return {
                "exploit_probability": 0.5,
                "risk_level": "MEDIUM",
                "block_count": block_count,
                "edge_count":  edge_count,
                "available":   False,
            }

        node_features = torch.tensor(
            [n["features"] for n in graph["nodes"]], dtype=torch.float32
        )
        edges = graph["edge_index"]
        if edges:
            edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
        else:
            edge_index = torch.zeros((2, 0), dtype=torch.long)

        batch = torch.zeros(node_features.size(0), dtype=torch.long)

        result = self.model.predict(node_features, edge_index, batch)
        pred   = result[0]

        return {
            "exploit_probability": pred["exploit_probability"],
            "risk_level":          pred["risk_level"],
            "block_count":         block_count,
            "edge_count":          edge_count,
            "available":           True,
        }
