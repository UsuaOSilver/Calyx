"""
models/gnn/model.py

Calyx GNN Model — 3-layer Graph Convolutional Network for exploit detection.

Architecture:
  - 3-layer GCN (GraphConvLayer): degree-normalized mean aggregation + LayerNorm
  - Node feature dim: 16  |  Hidden dim: 64  |  Output: binary (0=benign, 1=exploit)
"""

import torch
import torch.nn as nn
import torch.nn.functional as F


class GraphConvLayer(nn.Module):
    """Single GCN layer: mean-pool neighbors + linear transform + LayerNorm + ReLU."""

    def __init__(self, in_dim: int, out_dim: int):
        super().__init__()
        self.linear = nn.Linear(in_dim, out_dim)
        self.norm   = nn.LayerNorm(out_dim)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        N = x.size(0)
        if edge_index.size(1) == 0:
            return F.relu(self.norm(self.linear(x)))
        src, dst = edge_index[0], edge_index[1]
        agg = torch.zeros(N, x.size(1), device=x.device)
        agg.index_add_(0, dst, x[src])
        deg = torch.zeros(N, device=x.device)
        deg.index_add_(0, dst, torch.ones(src.size(0), device=x.device))
        agg = agg / deg.clamp(min=1).unsqueeze(1)
        return F.relu(self.norm(self.linear(x + agg)))


class CalyxGNN(nn.Module):
    """3-layer GCN for exploit detection. Input: CFG graph. Output: exploit probability."""

    def __init__(self, node_feature_dim: int = 16, edge_feature_dim: int = 8,
                 hidden_dim: int = 64, dropout: float = 0.3):
        super().__init__()
        self.node_feature_dim = node_feature_dim
        self.hidden_dim       = hidden_dim
        self.conv1 = GraphConvLayer(node_feature_dim, hidden_dim)
        self.conv2 = GraphConvLayer(hidden_dim, hidden_dim)
        self.conv3 = GraphConvLayer(hidden_dim, hidden_dim // 2)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim // 2, 32), nn.ReLU(),
            nn.Dropout(dropout), nn.Linear(32, 1),
        )
        self.dropout = nn.Dropout(dropout)

    def forward(self, node_features, edge_index, batch):
        x = node_features
        x = self.dropout(self.conv1(x, edge_index))
        x = self.dropout(self.conv2(x, edge_index))
        x = self.conv3(x, edge_index)
        num_graphs = batch.max().item() + 1
        graph_emb  = torch.zeros(int(num_graphs), x.size(1), device=x.device)
        graph_emb.index_add_(0, batch, x)
        counts = torch.zeros(int(num_graphs), device=x.device)
        counts.index_add_(0, batch, torch.ones(batch.size(0), device=x.device))
        graph_emb = graph_emb / counts.unsqueeze(1).clamp(min=1)
        return self.classifier(graph_emb).squeeze(1)

    def predict(self, node_features, edge_index, batch) -> list:
        self.eval()
        with torch.no_grad():
            probs = torch.sigmoid(self.forward(node_features, edge_index, batch))
        results = []
        for prob in probs.cpu().tolist():
            risk = "HIGH" if prob >= 0.8 else ("MEDIUM" if prob >= 0.5 else "LOW")
            results.append({"exploit_probability": round(prob, 4), "risk_level": risk})
        return results
