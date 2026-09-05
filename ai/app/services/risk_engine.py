"""Risk scoring engine."""

from __future__ import annotations

from typing import Any

try:
    import networkx as nx
except Exception:  # Python 3.14 + older networkx can fail at import
    nx = None  # type: ignore[assignment]


CRITICAL_ASSETS = {"server", "router", "database"}
HIGH_VALUE_PORTS = {22, 80, 443, 3389, 5432, 3306, 8080}


class RiskEngine:
    def compute(
        self,
        entity_type: str,
        entity_id: str,
        graph_snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        if nx is None:
            raise RuntimeError(
                "networkx is unavailable in this Python environment; "
                "install a compatible networkx version or use Python 3.11/3.12"
            )

        nodes = graph_snapshot.get("nodes", [])
        edges = graph_snapshot.get("edges", [])

        G = nx.DiGraph()
        for edge in edges:
            G.add_edge(edge.get("source"), edge.get("target"), **edge)

        target_node = self._find_entity(entity_id, nodes)
        entity_name = target_node.get("ip", entity_id) if target_node else entity_id

        node_risk = self._compute_node_risk(target_node, G)
        subnet_risk = self._compute_subnet_risk(target_node, nodes)
        dept_risk = self._compute_department_risk(target_node)
        org_risk = self._compute_organization_risk(nodes, edges)
        propagation_risk = self._compute_propagation_risk(entity_id, G, nodes)
        business_impact = self._compute_business_impact(target_node, propagation_risk)

        return {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "entity_name": entity_name,
            "node_risk": round(node_risk, 4),
            "subnet_risk": round(subnet_risk, 4),
            "department_risk": round(dept_risk, 4),
            "organization_risk": round(org_risk, 4),
            "propagation_risk": round(propagation_risk, 4),
            "business_impact": round(business_impact, 4),
            "factors": {
                "failed_logins": target_node.get("failed_logins", 0) if target_node else 0,
                "connection_count": target_node.get("connections", 0) if target_node else 0,
                "open_ports": len(target_node.get("ports", [])) if target_node else 0,
                "graph_centrality": round(float(nx.degree_centrality(G).get(entity_id, 0)), 4) if G.has_node(entity_id) else 0,
                "compromised_neighbors": self._count_compromised_neighbors(entity_id, nodes, G),
            },
        }

    def _find_entity(self, entity_id: str, nodes: list[dict]) -> dict | None:
        for node in nodes:
            if node.get("id") == entity_id or node.get("ip") == entity_id:
                return node
        return None

    def _compute_node_risk(self, node: dict | None, G: nx.DiGraph) -> float:
        if not node:
            return 0.1
        risk = 0.0
        risk += min(node.get("failed_logins", 0) * 0.15, 0.4)
        risk += min(node.get("connections", 0) / 100, 0.3)
        risk += min(node.get("packets", 0) / 10000, 0.2)
        if node.get("type") in CRITICAL_ASSETS:
            risk += 0.15
        ports = node.get("ports", [])
        if any(p in HIGH_VALUE_PORTS for p in ports):
            risk += 0.1
        node_id = node.get("id", "")
        if G.has_node(node_id):
            risk += min(nx.degree_centrality(G).get(node_id, 0) * 0.5, 0.2)
        return min(risk, 1.0)

    def _compute_subnet_risk(self, node: dict | None, nodes: list[dict]) -> float:
        if not node:
            return 0.1
        ip = node.get("ip", "")
        subnet = ".".join(ip.split(".")[:3]) if ip else ""
        subnet_nodes = [n for n in nodes if n.get("ip", "").startswith(subnet)]
        if not subnet_nodes:
            return 0.1
        risks = [self._compute_node_risk(n, nx.DiGraph()) for n in subnet_nodes]
        return sum(risks) / len(risks)

    def _compute_department_risk(self, node: dict | None) -> float:
        if not node:
            return 0.1
        dept_map = {"server": 0.7, "router": 0.6, "iot_device": 0.5, "host": 0.4, "user": 0.3}
        return dept_map.get(node.get("type", "host"), 0.4)

    def _compute_organization_risk(self, nodes: list[dict], edges: list[dict]) -> float:
        if not nodes:
            return 0.0
        total_risk = sum(self._compute_node_risk(n, nx.DiGraph()) for n in nodes)
        base = total_risk / len(nodes)
        edge_factor = min(len(edges) / max(len(nodes) * 5, 1), 0.3)
        return min(base + edge_factor, 1.0)

    def _compute_propagation_risk(self, entity_id: str, G: nx.DiGraph, nodes: list[dict]) -> float:
        if not G.has_node(entity_id):
            return 0.1
        try:
            reachable = nx.descendants(G, entity_id)
            reachable_risk = sum(
                self._compute_node_risk(self._find_entity(n, nodes), G)
                for n in list(reachable)[:20]
            )
            return min(reachable_risk / max(len(reachable), 1), 1.0)
        except Exception:
            return 0.2

    def _compute_business_impact(self, node: dict | None, propagation_risk: float) -> float:
        if not node:
            return 0.1
        asset_weight = {"server": 0.9, "router": 0.8, "iot_device": 0.5, "host": 0.4}.get(
            node.get("type", "host"), 0.4,
        )
        return min(asset_weight * 0.6 + propagation_risk * 0.4, 1.0)

    def _count_compromised_neighbors(self, entity_id: str, nodes: list[dict], G: nx.DiGraph) -> int:
        if not G.has_node(entity_id):
            return 0
        neighbors = set(G.successors(entity_id)) | set(G.predecessors(entity_id))
        return sum(
            1 for n in neighbors
            if (self._find_entity(n, nodes) or {}).get("failed_logins", 0) > 3
        )


risk_engine = RiskEngine()
