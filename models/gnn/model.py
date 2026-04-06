"""
Calyx GNN Model
Graph Neural Network for detecting exploit patterns in transaction graphs

Architecture:
  - 3-layer Graph Convolutional Network (GCN)
  - Node feature dim: 16
  - Hidden dim: 64
  - Output: binary classification (0=benign, 1=exploit)

Why GCN:
  Transactions are naturally graphs — accounts are nodes, function calls
  are edges. GCN propagates information across neighbors, letting the
  model learn "this account called a flashloan provider, then called
  a victim contract, then drained funds" as a structural pattern.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F


class GraphConvLayer(nn.Module):
    """
    Single GCN layer: aggregates neighbor features via mean pooling,
    then applies a linear transform + activation.

    Math: H' = ReLU(D^-1 * A * H * W)
    where A = adjacency, D = degree matrix, H = node features, W = weights
    """

    def __init__(self, in_dim: int, out_dim: int):
        super().__init__()
        self.linear = nn.Linear(in_dim, out_dim)
        self.norm   = nn.LayerNorm(out_dim)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x:          [N, in_dim]  node features
            edge_index: [2, E]       edge list (src, dst)
        Returns:
            [N, out_dim] updated node features
        """
        N = x.size(0)

        if edge_index.size(1) == 0:
            # No edges — just apply linear transform
            return F.relu(self.norm(self.linear(x)))

        src, dst = edge_index[0], edge_index[1]

        # Aggregate: for each node sum neighbor features
        agg = torch.zeros(N, x.size(1), device=x.device)
        agg.index_add_(0, dst, x[src])

        # Degree-normalize
        deg = torch.zeros(N, device=x.device)
        deg.index_add_(0, dst, torch.ones(src.size(0), device=x.device))
        deg = deg.clamp(min=1).unsqueeze(1)
        agg = agg / deg

        # Combine self + neighbors
        combined = x + agg

        return F.relu(self.norm(self.linear(combined)))


class CalyxGNN(nn.Module):
    """
    3-layer GCN for exploit detection.

    Input:  transaction graph (node features + edge index)
    Output: probability of exploit (0-1)
    """

    def __init__(
        self,
        node_feature_dim: int = 16,
        edge_feature_dim: int = 8,
        hidden_dim: int       = 64,
        dropout: float        = 0.3,
    ):
        super().__init__()

        self.node_feature_dim = node_feature_dim
        self.hidden_dim       = hidden_dim

        # GCN layers
        self.conv1 = GraphConvLayer(node_feature_dim, hidden_dim)
        self.conv2 = GraphConvLayer(hidden_dim, hidden_dim)
        self.conv3 = GraphConvLayer(hidden_dim, hidden_dim // 2)

        # Graph-level readout: mean+max pool → MLP classifier
        # Concatenating mean and max gives the classifier both "overall distribution"
        # and "does any block have X" signal — critical for large contracts where
        # mean pooling dilutes exploit-specific blocks buried among 1000+ benign blocks.
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, 32),  # hidden_dim = 2 * (hidden_dim // 2) from concat
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(32, 1),
        )

        self.dropout = nn.Dropout(dropout)

    def forward(
        self,
        node_features: torch.Tensor,  # [N, 16]
        edge_index:    torch.Tensor,  # [2, E]
        batch:         torch.Tensor,  # [N] — which graph each node belongs to
    ) -> torch.Tensor:
        """
        Returns:
            [B] logits (one per graph in batch)
        """
        x = node_features

        # Message passing
        x = self.conv1(x, edge_index)
        x = self.dropout(x)

        x = self.conv2(x, edge_index)
        x = self.dropout(x)

        x = self.conv3(x, edge_index)

        # Global mean + max pooling: aggregate all nodes per graph
        num_graphs = int(batch.max().item() + 1)
        feat_dim   = x.size(1)

        # Mean pooling
        mean_emb = torch.zeros(num_graphs, feat_dim, device=x.device)
        counts   = torch.zeros(num_graphs, device=x.device)
        mean_emb.index_add_(0, batch, x)
        counts.index_add_(0, batch, torch.ones(batch.size(0), device=x.device))
        mean_emb = mean_emb / counts.unsqueeze(1).clamp(min=1)

        # Max pooling — captures "does ANY block have exploit signal"
        max_emb = torch.full((num_graphs, feat_dim), float('-inf'), device=x.device)
        max_emb.scatter_reduce_(0, batch.unsqueeze(1).expand_as(x), x, reduce='amax',
                                include_self=True)
        max_emb = torch.nan_to_num(max_emb, nan=0.0, posinf=0.0, neginf=0.0)

        graph_emb = torch.cat([mean_emb, max_emb], dim=1)  # [B, hidden_dim]

        # Classification
        logits = self.classifier(graph_emb).squeeze(1)   # [B]
        return logits

    def predict(
        self,
        node_features: torch.Tensor,
        edge_index:    torch.Tensor,
        batch:         torch.Tensor,
    ) -> dict:
        """
        Convenience method: returns probability + risk label.
        """
        self.eval()
        with torch.no_grad():
            logits = self.forward(node_features, edge_index, batch)
            probs  = torch.sigmoid(logits)

        results = []
        for prob in probs.cpu().tolist():
            if prob >= 0.8:
                risk = "HIGH"
            elif prob >= 0.5:
                risk = "MEDIUM"
            else:
                risk = "LOW"
            results.append({"exploit_probability": round(prob, 4), "risk_level": risk})

        return results
