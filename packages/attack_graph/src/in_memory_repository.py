"""
InMemoryAttackGraphRepository: High-performance in-memory graph repository with BFS pathfinding.
Provides full fidelity for local execution, unit tests, and disconnected environments.
"""

from typing import List, Dict, Any, Optional
from collections import deque

from packages.attack_graph.src.models import (
    GraphEntityType,
    GraphRelationType,
    GraphNode,
    GraphEdge,
    AttackGraphData,
    AttackPath
)
from packages.attack_graph.src.repository import AttackGraphRepository


class InMemoryAttackGraphRepository(AttackGraphRepository):
    def __init__(self):
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._adj_out: Dict[str, List[GraphEdge]] = {}
        self._adj_in: Dict[str, List[GraphEdge]] = {}

    def create_entity(
        self,
        entity_type: GraphEntityType,
        entity_id: str,
        name: str,
        properties: Optional[Dict[str, Any]] = None
    ) -> GraphNode:
        node = GraphNode(
            id=entity_id,
            label=entity_type.value,
            name=name,
            properties=properties or {}
        )
        self._nodes[entity_id] = node
        self._adj_out.setdefault(entity_id, [])
        self._adj_in.setdefault(entity_id, [])
        return node

    def create_relationship(
        self,
        from_id: str,
        relation_type: GraphRelationType,
        to_id: str,
        properties: Optional[Dict[str, Any]] = None
    ) -> GraphEdge:
        edge = GraphEdge(
            source=from_id,
            target=to_id,
            relation=relation_type.value,
            properties=properties or {}
        )
        # Avoid duplicate identical edges
        for existing in self._edges:
            if existing.source == from_id and existing.target == to_id and existing.relation == relation_type.value:
                existing.properties.update(properties or {})
                return existing

        self._edges.append(edge)
        self._adj_out.setdefault(from_id, []).append(edge)
        self._adj_in.setdefault(to_id, []).append(edge)
        return edge

    def find_entity(self, entity_id: str) -> Optional[GraphNode]:
        return self._nodes.get(entity_id)

    def find_related(
        self,
        entity_id: str,
        relation_type: Optional[GraphRelationType] = None,
        direction: str = "OUT"
    ) -> List[GraphNode]:
        matched_nodes: List[GraphNode] = []
        
        if direction in ["OUT", "BOTH"]:
            for edge in self._adj_out.get(entity_id, []):
                if relation_type is None or edge.relation == relation_type.value:
                    if edge.target in self._nodes:
                        matched_nodes.append(self._nodes[edge.target])

        if direction in ["IN", "BOTH"]:
            for edge in self._adj_in.get(entity_id, []):
                if relation_type is None or edge.relation == relation_type.value:
                    if edge.source in self._nodes:
                        matched_nodes.append(self._nodes[edge.source])

        return matched_nodes

    def find_attack_paths(
        self,
        start_entity_id: str,
        target_entity_id: str,
        max_depth: int = 5
    ) -> List[AttackPath]:
        """Finds directed attack paths from start to target using BFS."""
        if start_entity_id not in self._nodes or target_entity_id not in self._nodes:
            return []

        paths: List[AttackPath] = []
        queue = deque([([start_entity_id], [])])  # (node_path, edge_path)

        while queue:
            current_nodes, current_edges = queue.popleft()
            current_node = current_nodes[-1]

            if current_node == target_entity_id:
                path_desc = " -> ".join([self._nodes[nid].name for nid in current_nodes])
                paths.append(
                    AttackPath(
                        path_id=f"path-{len(paths) + 1}",
                        start_entity=start_entity_id,
                        target_entity=target_entity_id,
                        length=len(current_edges),
                        steps=current_nodes,
                        description=path_desc
                    )
                )
                continue

            if len(current_edges) >= max_depth:
                continue

            for edge in self._adj_out.get(current_node, []):
                if edge.target not in current_nodes:  # Avoid cycles
                    queue.append((current_nodes + [edge.target], current_edges + [edge]))

        return paths

    def find_attack_chain(self, root_entity_id: str) -> AttackGraphData:
        """Extracts connected subgraph starting from root entity."""
        visited_nodes = set()
        visited_edges: List[GraphEdge] = []
        visited_edge_keys = set()
        queue = deque([root_entity_id])

        while queue:
            curr = queue.popleft()
            if curr in visited_nodes or curr not in self._nodes:
                continue
            visited_nodes.add(curr)

            for edge in self._adj_out.get(curr, []):
                edge_key = (edge.source, edge.relation, edge.target)
                if edge_key not in visited_edge_keys:
                    visited_edge_keys.add(edge_key)
                    visited_edges.append(edge)
                if edge.target not in visited_nodes:
                    queue.append(edge.target)

            for edge in self._adj_in.get(curr, []):
                edge_key = (edge.source, edge.relation, edge.target)
                if edge_key not in visited_edge_keys:
                    visited_edge_keys.add(edge_key)
                    visited_edges.append(edge)
                if edge.source not in visited_nodes:
                    queue.append(edge.source)

        nodes_list = [self._nodes[nid] for nid in visited_nodes]
        return AttackGraphData(nodes=nodes_list, edges=visited_edges)

    def upsert_observation(
        self,
        email_id: str,
        sender_domain: str,
        recipient_email: str,
        target_asset_host: str,
        cve_id: Optional[str] = None,
        session_id: Optional[str] = None,
        campaign_name: Optional[str] = None,
        threat_actor: Optional[str] = None
    ) -> AttackGraphData:
        # 1. Threat Actor & Campaign
        actor_id = f"actor-{threat_actor.lower().replace(' ', '-')}" if threat_actor else "actor-unc-cluster"
        self.create_entity(GraphEntityType.THREAT_ACTOR, actor_id, threat_actor or "Uncategorized Threat Group")

        camp_id = f"camp-{campaign_name.lower().replace(' ', '-')}" if campaign_name else "camp-spearphish-q3"
        self.create_entity(GraphEntityType.CAMPAIGN, camp_id, campaign_name or "Q3 Executive Phishing Campaign")
        self.create_relationship(actor_id, GraphRelationType.ORCHESTRATES, camp_id)

        # 2. Email Entity
        self.create_entity(GraphEntityType.EMAIL, email_id, f"Email: {email_id}", {"sender_domain": sender_domain})
        self.create_relationship(camp_id, GraphRelationType.DELIVERS, email_id)

        # 3. Target Identity
        ident_id = f"ident-{recipient_email}"
        self.create_entity(GraphEntityType.IDENTITY, ident_id, recipient_email)
        self.create_relationship(email_id, GraphRelationType.TARGETS, ident_id)

        # 4. Target Asset
        asset_id = f"asset-{target_asset_host}"
        self.create_entity(GraphEntityType.ASSET, asset_id, target_asset_host)
        self.create_relationship(email_id, GraphRelationType.AFFECTS, asset_id)

        # 5. CVE
        if cve_id:
            cve_node_id = f"cve-{cve_id.lower()}"
            self.create_entity(GraphEntityType.CVE, cve_node_id, cve_id)
            self.create_relationship(email_id, GraphRelationType.EXPLOITS, cve_node_id)
            self.create_relationship(asset_id, GraphRelationType.INDICATES, cve_node_id)

        # 6. Session
        if session_id:
            sess_node_id = f"sess-{session_id}"
            self.create_entity(GraphEntityType.SESSION, sess_node_id, f"Session: {session_id}")
            self.create_relationship(ident_id, GraphRelationType.OWNS, sess_node_id)
            if cve_id:
                self.create_relationship(f"cve-{cve_id.lower()}", GraphRelationType.TRIGGERS, sess_node_id)

        return self.find_attack_chain(email_id)

    def to_graph_json(self) -> AttackGraphData:
        return AttackGraphData(
            nodes=list(self._nodes.values()),
            edges=self._edges
        )
