"""
Abstract Interface for the Attack Graph Repository.
All higher-level business logic, agents, and API endpoints depend exclusively on this contract.
No Cypher queries are allowed to bleed into business logic.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

from packages.attack_graph.src.models import (
    GraphEntityType,
    GraphRelationType,
    GraphNode,
    GraphEdge,
    AttackGraphData,
    AttackPath
)


class AttackGraphRepository(ABC):
    """
    Abstract contract for graph operations across Neo4j and In-Memory implementations.
    """

    @abstractmethod
    def create_entity(
        self,
        entity_type: GraphEntityType,
        entity_id: str,
        name: str,
        properties: Optional[Dict[str, Any]] = None
    ) -> GraphNode:
        """Creates or updates an entity node in the attack graph."""
        pass

    @abstractmethod
    def create_relationship(
        self,
        from_id: str,
        relation_type: GraphRelationType,
        to_id: str,
        properties: Optional[Dict[str, Any]] = None
    ) -> GraphEdge:
        """Creates a directed relationship between two entities."""
        pass

    @abstractmethod
    def find_entity(self, entity_id: str) -> Optional[GraphNode]:
        """Finds an entity node by its unique ID."""
        pass

    @abstractmethod
    def find_related(
        self,
        entity_id: str,
        relation_type: Optional[GraphRelationType] = None,
        direction: str = "OUT"  # OUT, IN, BOTH
    ) -> List[GraphNode]:
        """Finds entities directly connected to a given entity."""
        pass

    @abstractmethod
    def find_attack_paths(
        self,
        start_entity_id: str,
        target_entity_id: str,
        max_depth: int = 5
    ) -> List[AttackPath]:
        """Finds all traversal paths connecting an adversary/email to a target identity/asset."""
        pass

    @abstractmethod
    def find_attack_chain(self, root_entity_id: str) -> AttackGraphData:
        """Extracts the complete connected attack subgraph rooted at a specific email or incident."""
        pass

    @abstractmethod
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
        """
        Convenience method to construct the full attack chain graph in a single atomic transaction.
        """
        pass

    @abstractmethod
    def to_graph_json(self) -> AttackGraphData:
        """Returns the entire graph formatted for frontend Cytoscape/D3/Vis.js visualization."""
        pass
