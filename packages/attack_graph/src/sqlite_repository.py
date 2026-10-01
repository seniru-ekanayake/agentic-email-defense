"""
SqliteAttackGraphRepository: Durable disk-backed Attack Graph Repository.
Inherits from InMemoryAttackGraphRepository to provide full graph traversal,
BFS attack pathfinding, and observation upserts, while durably persisting
nodes and relationships to SQLite via DurableStorage.
"""

from typing import List, Dict, Any, Optional
from packages.attack_graph.src.models import (
    GraphEntityType,
    GraphRelationType,
    GraphNode,
    GraphEdge,
    AttackGraphData,
    AttackPath
)
from packages.attack_graph.src.in_memory_repository import InMemoryAttackGraphRepository
from apps.agents.core.durable_storage import DurableStorage


class SqliteAttackGraphRepository(InMemoryAttackGraphRepository):
    """
    Durable SQLite-backed Attack Graph repository.
    """

    def __init__(self, storage: Optional[DurableStorage] = None):
        super().__init__()
        self.storage = storage or DurableStorage.get_instance()
        self._load_from_storage()

    def _load_from_storage(self):
        try:
            nodes_data, edges_data = self.storage.load_graph_data()
            for nd in nodes_data:
                node = GraphNode(
                    id=nd["id"],
                    label=nd["label"],
                    name=nd["name"],
                    properties=nd.get("properties", {})
                )
                self._nodes[node.id] = node
                self._adj_out.setdefault(node.id, [])
                self._adj_in.setdefault(node.id, [])

            for ed in edges_data:
                edge = GraphEdge(
                    source=ed["source"],
                    target=ed["target"],
                    relation=ed["relation"],
                    properties=ed.get("properties", {})
                )
                self._edges.append(edge)
                self._adj_out.setdefault(edge.source, []).append(edge)
                self._adj_in.setdefault(edge.target, []).append(edge)
        except Exception:
            pass

    def create_entity(
        self,
        entity_type: GraphEntityType,
        entity_id: str,
        name: str,
        properties: Optional[Dict[str, Any]] = None
    ) -> GraphNode:
        node = super().create_entity(entity_type, entity_id, name, properties)
        try:
            self.storage.save_graph_node(entity_id, entity_type.value, name, properties or {})
        except Exception:
            pass
        return node

    def create_relationship(
        self,
        from_id: str,
        relation_type: GraphRelationType,
        to_id: str,
        properties: Optional[Dict[str, Any]] = None
    ) -> GraphEdge:
        edge = super().create_relationship(from_id, relation_type, to_id, properties)
        try:
            self.storage.save_graph_edge(from_id, to_id, relation_type.value, properties or {})
        except Exception:
            pass
        return edge
