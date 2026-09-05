"""Temporal Graph Neural Network for Cyber Attack Prediction."""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATConv, SAGEConv, GCNConv


ATTACK_STAGES = [
    "normal", "reconnaissance", "scanning", "credential_attack",
    "privilege_escalation", "lateral_movement", "persistence",
    "data_exfiltration", "impact",
]

ATTACK_TYPES = [
    "Normal", "DDoS", "Probe", "R2L", "U2R", "Botnet", "Web Attack",
    "Infiltration", "Brute Force", "DoS", "Heartbleed",
]

STAGE_TRANSITIONS = {
    "normal": "reconnaissance",
    "reconnaissance": "scanning",
    "scanning": "credential_attack",
    "credential_attack": "privilege_escalation",
    "privilege_escalation": "lateral_movement",
    "lateral_movement": "persistence",
    "persistence": "data_exfiltration",
    "data_exfiltration": "impact",
    "impact": "impact",
}


class TemporalAttention(nn.Module):
    def __init__(self, hidden_dim: int, num_heads: int = 4):
        super().__init__()
        self.attention = nn.MultiheadAttention(hidden_dim, num_heads, batch_first=True)
        self.norm = nn.LayerNorm(hidden_dim)

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        if x.dim() == 2:
            x = x.unsqueeze(0)
        attn_out, attn_weights = self.attention(x, x, x)
        return self.norm(attn_out.squeeze(0)), attn_weights


class TGNNModel(nn.Module):
    """
    Temporal Graph Neural Network combining GAT + GraphSAGE layers
    with temporal attention for attack prediction.
    """

    def __init__(
        self,
        node_features: int = 16,
        hidden_dim: int = 64,
        num_gat_heads: int = 4,
        num_layers: int = 3,
        num_attack_types: int = len(ATTACK_TYPES),
        num_stages: int = len(ATTACK_STAGES),
        dropout: float = 0.3,
        architecture: str = "gat",
    ):
        super().__init__()
        self.architecture = architecture
        self.hidden_dim = hidden_dim
        self.node_features = node_features

        # Input feature standardization. Populated from training-set statistics
        # (see TrainingService) and saved in the checkpoint, so train and
        # inference normalize identically. Defaults are identity (mean 0, std 1)
        # so checkpoints trained before this change still behave unchanged.
        self.register_buffer("feat_mean", torch.zeros(node_features))
        self.register_buffer("feat_std", torch.ones(node_features))

        self.input_proj = nn.Linear(node_features, hidden_dim)
        self.temporal_encoder = nn.GRU(hidden_dim, hidden_dim, batch_first=True)

        if architecture == "gat":
            self.conv1 = GATConv(hidden_dim, hidden_dim // num_gat_heads, heads=num_gat_heads, dropout=dropout)
            self.conv2 = GATConv(hidden_dim, hidden_dim // num_gat_heads, heads=num_gat_heads, dropout=dropout)
        elif architecture == "graphsage":
            self.conv1 = SAGEConv(hidden_dim, hidden_dim)
            self.conv2 = SAGEConv(hidden_dim, hidden_dim)
        elif architecture == "gcn":
            self.conv1 = GCNConv(hidden_dim, hidden_dim)
            self.conv2 = GCNConv(hidden_dim, hidden_dim)
        else:
            self.conv1 = GATConv(hidden_dim, hidden_dim // num_gat_heads, heads=num_gat_heads, dropout=dropout)
            self.conv2 = GATConv(hidden_dim, hidden_dim // num_gat_heads, heads=num_gat_heads, dropout=dropout)

        self.temporal_attention = TemporalAttention(hidden_dim)
        self.dropout = nn.Dropout(dropout)

        self.attack_classifier = nn.Linear(hidden_dim, num_attack_types)
        self.stage_classifier = nn.Linear(hidden_dim, num_stages)
        self.next_stage_classifier = nn.Linear(hidden_dim, num_stages)
        self.risk_regressor = nn.Linear(hidden_dim, 1)
        self.compromise_classifier = nn.Linear(hidden_dim, 2)

        self.attention_weights: torch.Tensor | None = None

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        temporal_seq: torch.Tensor | None = None,
    ) -> dict[str, torch.Tensor]:
        x = (x - self.feat_mean) / (self.feat_std + 1e-6)
        h = F.relu(self.input_proj(x))
        h = F.relu(self.conv1(h, edge_index))
        h = self.dropout(h)
        h = F.relu(self.conv2(h, edge_index))
        h, attn = self.temporal_attention(h)
        self.attention_weights = attn

        if temporal_seq is not None and temporal_seq.size(0) > 0:
            _, gru_out = self.temporal_encoder(temporal_seq)
            h = h + gru_out.squeeze(0)

        graph_embedding = h.mean(dim=0, keepdim=True)

        attack_logits = self.attack_classifier(graph_embedding)
        stage_logits = self.stage_classifier(graph_embedding)
        next_stage_logits = self.next_stage_classifier(graph_embedding)
        risk_score = torch.sigmoid(self.risk_regressor(graph_embedding))
        compromise_logits = self.compromise_classifier(graph_embedding)

        return {
            "attack_logits": attack_logits,
            "stage_logits": stage_logits,
            "next_stage_logits": next_stage_logits,
            "risk_score": risk_score,
            "compromise_logits": compromise_logits,
            "node_embeddings": h,
            "attention_weights": attn,
        }

    def get_attention_weights(self) -> torch.Tensor | None:
        return self.attention_weights
