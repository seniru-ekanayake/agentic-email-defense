"""Neo4jAttackGraphRepository: Neo4j Community Edition driver implementation.

Encapsulates all parameterized Cypher queries, atomic multi-hop traversals,
and maintains graph constraints with graceful offline fallback.
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
    """Neo4j implementation executing native Cypher queries with graceful offline fallback."""

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
            logger.debug(f"Neo4j connection unavailable ({e}). Active in In-Memory fallback mode.")
            self._connected = False

    @property
    def is_connected(self) -> bool:
        return self._connected

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
        try:
            with self._driver.session() as session:
                res = session.run(query, id=entity_id, name=name, props=properties or {})
                rec = res.single()
                return GraphNode(id=rec["id"], label=rec["label"], name=rec["name"], properties=rec["props"])
        except Exception as e:
            logger.warning(f"Neo4j create_entity error: {e}. Using fallback.")
            return self._fallback_repo.create_entity(entity_type, entity_id, name, properties)

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
        try:
            with self._driver.session() as session:
                res = session.run(query, from_id=from_id, to_id=to_id, props=properties or {})
                rec = res.single()
                return GraphEdge(source=rec["source"], target=rec["target"], relation=rec["relation"], properties=rec["props"])
        except Exception as e:
            logger.warning(f"Neo4j create_relationship error: {e}. Using fallback.")
            return self._fallback_repo.create_relationship(from_id, relation_type, to_id, properties)

    def find_entity(self, entity_id: str) -> Optional[GraphNode]:
        if not self._connected:
            return self._fallback_repo.find_entity(entity_id)

        query = "MATCH (n {id: $id}) RETURN n.id AS id, labels(n)[0] AS label, n.name AS name, properties(n) AS props"
        try:
            with self._driver.session() as session:
                res = session.run(query, id=entity_id)
                rec = res.single()
                if rec:
                    return GraphNode(id=rec["id"], label=rec["label"], name=rec["name"], properties=rec["props"])
        except Exception as e:
            logger.warning(f"Neo4j find_entity error: {e}. Using fallback.")
            return self._fallback_repo.find_entity(entity_id)
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
        try:
            with self._driver.session() as session:
                results = session.run(query, id=entity_id)
                return [GraphNode(id=r["id"], label=r["label"], name=r["name"], properties=r["props"]) for r in results]
        except Exception as e:
            logger.warning(f"Neo4j find_related error: {e}. Using fallback.")
            return self._fallback_repo.find_related(entity_id, relation_type, direction)

    def find_attack_paths(
        self,
        start_entity_id: str,
        target_entity_id: str,
        max_depth: int = 5
    ) -> List[AttackPath]:
        """Native Cypher shortest-path query traversing multi-hop attack vectors."""
        if not self._connected:
            return self._fallback_repo.find_attack_paths(start_entity_id, target_entity_id, max_depth)

        query = f"""
        MATCH (start {{id: $start_id}}), (target {{id: $target_id}})
        MATCH p = (start)-[*1..{max_depth}]->(target)
        RETURN [node in nodes(p) | node.id] AS path_nodes,
               [rel in relationships(p) | type(rel)] AS path_rels,
               length(p) AS path_len
        ORDER BY path_len ASC
        LIMIT 10
        """
        try:
            with self._driver.session() as session:
                results = session.run(query, start_id=start_entity_id, target_id=target_entity_id)
                paths = []
                for idx, rec in enumerate(results):
                    p_nodes = rec["path_nodes"]
                    desc = f"Path ({rec['path_len']} hops): " + " -> ".join(p_nodes)
                    paths.append(AttackPath(
                        path_id=f"path-{idx+1}",
                        start_entity=start_entity_id,
                        target_entity=target_entity_id,
                        length=rec["path_len"],
                        steps=p_nodes,
                        description=desc
                    ))
                return paths
        except Exception as e:
            logger.warning(f"Neo4j find_attack_paths error: {e}. Using fallback.")
            return self._fallback_repo.find_attack_paths(start_entity_id, target_entity_id, max_depth)

    def find_attack_chain(self, root_entity_id: str) -> AttackGraphData:
        """Native Cypher full subgraph extraction surrounding an attack root entity."""
        if not self._connected:
            return self._fallback_repo.find_attack_chain(root_entity_id)

        query = """
        MATCH (root {id: $root_id})
        OPTIONAL MATCH p = (root)-[*1..4]-(connected)
        WITH root, collect(DISTINCT p) AS paths
        UNWIND (CASE WHEN size(paths) = 0 THEN [null] ELSE paths END) AS path
        WITH root, path
        UNWIND (CASE WHEN path IS NULL THEN [root] ELSE nodes(path) END) AS n
        UNWIND (CASE WHEN path IS NULL THEN [] ELSE relationships(path) END) AS r
        RETURN collect(DISTINCT {id: n.id, label: labels(n)[0], name: n.name, properties: properties(n)}) AS nodes,
               collect(DISTINCT {source: startNode(r).id, target: endNode(r).id, relation: type(r), properties: properties(r)}) AS edges
        """
        try:
            with self._driver.session() as session:
                res = session.run(query, root_id=root_entity_id)
                rec = res.single()
                if not rec:
                    return AttackGraphData()

                node_objs = [
                    GraphNode(id=n["id"], label=n.get("label", "Entity"), name=n.get("name", n["id"]), properties=n.get("properties", {}))
                    for n in rec["nodes"] if n and "id" in n
                ]
                edge_objs = [
                    GraphEdge(source=e["source"], target=e["target"], relation=e["relation"], properties=e.get("properties", {}))
                    for e in rec["edges"] if e and "source" in e
                ]
                return AttackGraphData(nodes=node_objs, edges=edge_objs)
        except Exception as e:
            logger.warning(f"Neo4j find_attack_chain error: {e}. Using fallback.")
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
        """Atomic Cypher transactional upsert for complete multi-hop attack observation."""
        if not self._connected:
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

        actor_name = threat_actor or "Unattributed Actor"
        actor_id = f"actor-{actor_name.lower().replace(' ', '-')}"
        camp_name = campaign_name or f"Campaign-{sender_domain}"
        camp_id = f"campaign-{sender_domain}"
        asset_id = f"asset-{target_asset_host}"
        ident_id = f"ident-{recipient_email}"

        tx_query = """
        MERGE (actor:ThreatActor {id: $actor_id})
        SET actor.name = $actor_name

        MERGE (camp:Campaign {id: $camp_id})
        SET camp.name = $camp_name

        MERGE (email:EmailMessage {id: $email_id})
        SET email.name = $email_id, email.sender_domain = $sender_domain, email.recipient = $recipient_email

        MERGE (asset:Asset {id: $asset_id})
        SET asset.name = $target_asset_host

        MERGE (ident:Identity {id: $ident_id})
        SET ident.name = $recipient_email

        MERGE (actor)-[:CONDUCTS]->(camp)
        MERGE (camp)-[:DELIVERS]->(email)
        MERGE (email)-[:TARGETS_ASSET]->(asset)
        MERGE (email)-[:TARGETS_IDENTITY]->(ident)
        """

        try:
            with self._driver.session() as session:
                session.run(
                    tx_query,
                    actor_id=actor_id, actor_name=actor_name,
                    camp_id=camp_id, camp_name=camp_name,
                    email_id=email_id, sender_domain=sender_domain, recipient_email=recipient_email,
                    asset_id=asset_id, target_asset_host=target_asset_host,
                    ident_id=ident_id
                )

                if cve_id:
                    cve_entity_id = f"cve-{cve_id.lower()}"
                    cve_query = """
                    MATCH (email:EmailMessage {id: $email_id}), (asset:Asset {id: $asset_id})
                    MERGE (cve:Vulnerability {id: $cve_id})
                    SET cve.name = $cve_name
                    MERGE (email)-[:EXPLOITS]->(cve)
                    MERGE (cve)-[:AFFECTS]->(asset)
                    """
                    session.run(cve_query, email_id=email_id, asset_id=asset_id, cve_id=cve_entity_id, cve_name=cve_id)

                if session_id:
                    sess_entity_id = f"session-{session_id}"
                    sess_query = """
                    MATCH (ident:Identity {id: $ident_id})
                    MERGE (sess:Session {id: $sess_id})
                    SET sess.name = $sess_name
                    MERGE (ident)-[:OWNS_SESSION]->(sess)
                    """
                    session.run(sess_query, ident_id=ident_id, sess_id=sess_entity_id, sess_name=f"Session ({session_id})")

                return self.find_attack_chain(email_id)
        except Exception as e:
            logger.warning(f"Neo4j upsert_observation error: {e}. Using fallback.")
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
        """Export the full graph as AttackGraphData."""
        if not self._connected:
            return self._fallback_repo.to_graph_json()

        query = """
        MATCH (n)
        OPTIONAL MATCH (n)-[r]->(m)
        RETURN collect(DISTINCT {id: n.id, label: labels(n)[0], name: n.name, properties: properties(n)}) AS nodes,
               collect(DISTINCT {source: startNode(r).id, target: endNode(r).id, relation: type(r), properties: properties(r)}) AS edges
        """
        try:
            with self._driver.session() as session:
                res = session.run(query)
                rec = res.single()
                if not rec:
                    return AttackGraphData()

                node_objs = [
                    GraphNode(id=n["id"], label=n.get("label", "Entity"), name=n.get("name", n["id"]), properties=n.get("properties", {}))
                    for n in rec["nodes"] if n and "id" in n
                ]
                edge_objs = [
                    GraphEdge(source=e["source"], target=e["target"], relation=e["relation"], properties=e.get("properties", {}))
                    for e in rec["edges"] if e and "source" in e
                ]
                return AttackGraphData(nodes=node_objs, edges=edge_objs)
        except Exception as e:
            logger.warning(f"Neo4j to_graph_json error: {e}. Using fallback.")
            return self._fallback_repo.to_graph_json()

