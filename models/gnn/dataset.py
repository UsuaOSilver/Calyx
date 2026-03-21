"""
Calyx GNN — Dataset loader
Reads processed .jsonl graph files and serves PyTorch tensors
"""

import json
import torch
from pathlib import Path
from torch.utils.data import Dataset, DataLoader
from typing import List, Tuple

PROCESSED_DIR = Path(__file__).resolve().parents[2] / "data" / "datasets" / "processed"


class TransactionGraphDataset(Dataset):
    def __init__(self, split: str = "train", processed_dir: Path = PROCESSED_DIR):
        self.graphs = []
        path = processed_dir / f"{split}.jsonl"

        if not path.exists():
            raise FileNotFoundError(f"Dataset not found: {path}")

        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    self.graphs.append(json.loads(line))

    def __len__(self):
        return len(self.graphs)

    def __getitem__(self, idx: int) -> dict:
        return self.graphs[idx]


def collate_graphs(batch: List[dict]) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
    """Custom collate: merges graphs into batched tensors"""
    all_nodes  = []
    all_edges  = []
    all_batch  = []
    all_labels = []

    node_offset = 0

    for graph_idx, graph in enumerate(batch):
        # Extract node features from nodes array
        node_feats = [n["features"] for n in graph["nodes"]]
        nodes = torch.tensor(node_feats, dtype=torch.float32)
        N = nodes.size(0)

        # Edge index
        edges = graph["edge_index"]
        if edges:
            edge_t = torch.tensor(edges, dtype=torch.long).t().contiguous()
            edge_t = edge_t + node_offset
        else:
            edge_t = torch.zeros((2, 0), dtype=torch.long)

        batch_ids = torch.full((N,), graph_idx, dtype=torch.long)

        all_nodes.append(nodes)
        all_edges.append(edge_t)
        all_batch.append(batch_ids)
        all_labels.append(graph["label"])

        node_offset += N

    node_features = torch.cat(all_nodes, dim=0)
    edge_index = torch.cat(all_edges, dim=1) if any(e.size(1) > 0 for e in all_edges) else torch.zeros((2, 0), dtype=torch.long)
    batch_tensor = torch.cat(all_batch, dim=0)
    labels = torch.tensor(all_labels, dtype=torch.float32)

    return node_features, edge_index, batch_tensor, labels


def get_dataloader(split: str = "train", batch_size: int = 32, shuffle: bool = True) -> DataLoader:
    dataset = TransactionGraphDataset(split=split)
    return DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=shuffle,
        collate_fn=collate_graphs,
        num_workers=0,
    )


if __name__ == "__main__":
    for split in ("train", "val", "test"):
        try:
            ds = TransactionGraphDataset(split=split)
            exploits = sum(1 for g in ds.graphs if g["label"] == 1)
            benign = sum(1 for g in ds.graphs if g["label"] == 0)
            print(f"{split:5s}: {len(ds):4d} graphs  ({exploits} exploits, {benign} benign)")
        except FileNotFoundError as e:
            print(f"{split:5s}: not found")
