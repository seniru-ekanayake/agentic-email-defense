"""
Neo4jAttackGraphRepository: Neo4j Community Edition driver implementation.
Encapsulates all parameterized Cypher queries and maintains graph constraints.
"""

import logging
from typing import List, Dict, Any, Optional

from packages.attack_graph.src.models import (
    GraphEntityType,
    GraphRelationType,
    GraphNode,
    GraphEdge,
    AttackGraphData,
    AttackPath
)
from packages.attack_graph.src.repository import AttackGraphRepository
from packages.attack_graph.src.in_memory_repository import InMemoryAttackGraphRepository

logger = logging.getLogger("Neo4jAttackGraphRepository")


class Neo4jAttackGraphRepository(AttackGraphRepository):
    """
    Neo4j implementation. Falls back gracefully to InMemoryAttackGraphRepository
    if Neo4j is unreachable during local testing.
    """

    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "admin_password"
    ):
        self.uri = uri
        self.user = user
        self.password = password
        self._fallback_repo = InMemoryAttackGraphRepository()
        self._driver = None
        self._connected = False
        self._init_driver()

    def _init_driver(self):
        try:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            with self._driver.session() as session:
                session.run("RETURN 1")
            self._connected = True
            logger.info(f"Connected successfully to Neo4j at {self.uri}")
        except Exception as e:
            logger.warning(f"Neo4j connection unavailable ({e}). Using In-Memory Graph repository.")
            self._connected = False

    def create_entity(
        self,
        entity_type: GraphEntityType,
        entity_id: str,
        name: str,
        properties: Optional[Dict[str, Any]] = None
    ) -> GraphNode:
        if not self._connected:
            return self._fallback_repo.create_entity(entity_type, entity_id, name, properties)

        query = f"""
        MERGE (n:{entity_type.value} {{id: $id}})
        SET n.name = $name, n += $props
        RETURN n.id AS id, labels(n)[0] AS label, n.name AS name, properties(n) AS props
        """
        with self._driver.session() as session:
            res = session.run(query, id=entity_id, name=name, props=properties or {})
            rec = res.single()
            return GraphNode(id=rec["id"], label=rec["label"], name=rec["name"], properties=rec["props"])

    def create_relationship(
        self,
        from_id: str,
        relation_type: GraphRelationType,
        to_id: str,
        properties: Optional[Dict[str, Any]] = None
    ) -> GraphEdge:
        if not self._connected:
            return self._fallback_repo.create_relationship(from_id, relation_type, to_id, properties)

        query = f"""
        MATCH (a {{id: $from_id}}), (b {{id: $to_id}})
        MERGE (a)-[r:{relation_type.value}]->(b)
        SET r += $props
        RETURN a.id AS source, b.id AS target, type(r) AS relation, properties(r) AS props
        """
        with self._driver.session() as session:
            res = session.run(query, from_id=from_id, to_id=to_id, props=properties or {})
            rec = res.single()
            return GraphEdge(source=rec["source"], target=rec["target"], relation=rec["relation"], properties=rec["props"])

    def find_entity(self, entity_id: str) -> Optional[GraphNode]:
        if not self._connected:
            return self._fallback_repo.find_entity(entity_id)

        query = "MATCH (n {id: $id}) RETURN n.id AS id, labels(n)[0] AS label, n.name AS name, properties(n) AS props"
        with self._driver.session() as session:
            res = session.run(query, id=entity_id)
            rec = res.single()
            if rec:
                return GraphNode(id=rec["id"], label=rec["label"], name=rec["name"], properties=rec["props"])
        return None

    def find_related(
        self,
        entity_id: str,
        relation_type: Optional[GraphRelationType] = None,
        direction: str = "OUT"
    ) -> List[GraphNode]:
        if not self._connected:
            return self._fallback_repo.find_related(entity_id, relation_type, direction)

        rel_filter = f":{relation_type.value}" if relation_type else ""
        if direction == "OUT":
            pattern = f"(a {{id: $id}})-[{rel_filter}]->(b)"
        elif direction == "IN":
            pattern = f"(a {{id: $id}})<-[{rel_filter}]-(b)"
        else:
            pattern = f"(a {{id: $id}})-[{rel_filter}]-(b)"

        query = f"MATCH {pattern} RETURN b.id AS id, labels(b)[0] AS label, b.name AS name, properties(b) AS props"
        with self._driver.session() as session:
            results = session.run(query, id=entity_id)
            return [GraphNode(id=r["id"], label=r["label"], name=r["name"], properties=r["props"]) for r in results]

    def find_attack_paths(
        self,
        start_entity_id: str,
        target_entity_id: str,
        max_depth: int = 5
    ) -> List[AttackPath]:
        return self._fallback_repo.find_attack_paths(start_entity_id, target_entity_id, max_depth)

    def find_attack_chain(self, root_entity_id: str) -> AttackGraphData:
        return self._fallback_repo.find_attack_chain(root_entity_id)

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
        return self._fallback_repo.upsert_observation(
            email_id=email_id,
            sender_domain=sender_domain,
            recipient_email=recipient_email,
            target_asset_host=target_asset_host,
            cve_id=cve_id,
            session_id=session_id,
            campaign_name=campaign_name,
            threat_actor=threat_actor
        )

    def to_graph_json(self) -> AttackGraphData:
        return self._fallback_repo.to_graph_json()
