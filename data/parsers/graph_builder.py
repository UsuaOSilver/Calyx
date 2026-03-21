"""Graph Builder - Working Version"""
import json
import random
import hashlib
from pathlib import Path
from collections import defaultdict

random.seed(42)

ROOT = Path(__file__).resolve().parents[2]
RAW_JSON = ROOT / "data" / "datasets" / "raw" / "findings_all.jsonl"
PROCESSED_DIR = ROOT / "data" / "datasets" / "processed"
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)


def hash_string(s):
    return int(hashlib.md5(s.encode()).hexdigest()[:8], 16)


class GraphBuilder:
    def __init__(self):
        self.node_dim = 16
        self.edge_dim = 8
        self.node_roles = ["initiator", "processor", "validator", "storage"]
        self.edge_types = ["call", "transfer", "read", "write", "delegate", "create"]
    
    def _generate_topology(self, finding):
        seed = hash_string(finding['report_id'])
        rng = random.Random(seed)
        num_nodes = rng.randint(2, 4)
        num_edges = rng.randint(1, 6)
        return num_nodes, num_edges, rng
    
    def _create_node_features(self, role, finding, rng):
        role_idx = self.node_roles.index(role)
        role_vec = [1.0 if i == role_idx else 0.0 for i in range(4)]
        features = role_vec + [rng.random() for _ in range(12)]
        return features
    
    def _create_edge_features(self, edge_type, rng):
        type_idx = self.edge_types.index(edge_type)
        type_vec = [1.0 if i == type_idx else 0.0 for i in range(6)]
        features = type_vec + [rng.random(), rng.random()]
        assert len(features) == 8
        return features
    
    def build_graph(self, finding):
        num_nodes, num_edges, rng = self._generate_topology(finding)
        roles = [rng.choice(self.node_roles) for _ in range(num_nodes)]
        
        nodes = []
        for role in roles:
            features = self._create_node_features(role, finding, rng)
            nodes.append({"role": role, "features": features})
        
        edges = []
        edge_index = []
        for _ in range(num_edges):
            src = rng.randint(0, num_nodes - 1)
            dst = rng.randint(0, num_nodes - 1)
            edge_type = rng.choice(self.edge_types)
            features = self._create_edge_features(edge_type, rng)
            edges.append({"type": edge_type, "features": features})
            edge_index.append([src, dst])
        
        is_exploit = finding['category'] != 'benign'
        
        return {
            "graph_id": finding['report_id'],
            "label": 1 if is_exploit else 0,
            "category": finding['category'],
            "num_nodes": num_nodes,
            "num_edges": num_edges,
            "nodes": nodes,
            "edges": edges,
            "edge_index": edge_index,
            "metadata": {
                "source": finding['source'],
                "severity": finding.get('severity', 'unknown'),
            }
        }


def load_findings():
    findings = []
    with open(RAW_JSON, 'r') as f:
        for line in f:
            findings.append(json.loads(line))
    return findings


def do_split(graphs, train_ratio=0.6, val_ratio=0.2):
    """Split graphs into train/val/test"""
    exploits = [g for g in graphs if g['label'] == 1]
    benign = [g for g in graphs if g['label'] == 0]
    
    random.shuffle(exploits)
    random.shuffle(benign)
    
    n_exploit = len(exploits)
    train_e = int(n_exploit * train_ratio)
    val_e = int(n_exploit * val_ratio)
    
    exploit_train = exploits[:train_e]
    exploit_val = exploits[train_e:train_e + val_e]
    exploit_test = exploits[train_e + val_e:]
    
    n_benign = len(benign)
    train_b = int(n_benign * train_ratio)
    val_b = int(n_benign * val_ratio)
    
    benign_train = benign[:train_b]
    benign_val = benign[train_b:train_b + val_b]
    benign_test = benign[train_b + val_b:]
    
    train = exploit_train + benign_train
    val = exploit_val + benign_val
    test = exploit_test + benign_test
    
    random.shuffle(train)
    random.shuffle(val)
    random.shuffle(test)
    
    return train, val, test


if __name__ == "__main__":
    findings = load_findings()
    print(f"Loaded {len(findings)} raw findings")
    
    builder = GraphBuilder()
    graphs = []
    
    print("Generating graphs...")
    for i, finding in enumerate(findings):
        graph = builder.build_graph(finding)
        graphs.append(graph)
        if (i + 1) % 500 == 0:
            print(f"  Generated {i+1}/{len(findings)} graphs...")
    
    print(f"Successfully generated {len(graphs)} graphs")
    
    # Use the renamed function to avoid scoping issues
    train, val, test = do_split(graphs)
    
    for split_name, split_data in [("train", train), ("val", val), ("test", test)]:
        output_path = PROCESSED_DIR / f"{split_name}.jsonl"
        with open(output_path, 'w') as f:
            for graph in split_data:
                f.write(json.dumps(graph) + '\n')
        print(f"✅ Saved {len(split_data)} graphs → {split_name}.jsonl")
    
    print("=" * 60)
    print("✅ Dataset generated successfully!")
    print(f"   Saved to: {PROCESSED_DIR}")
    print("=" * 60)
