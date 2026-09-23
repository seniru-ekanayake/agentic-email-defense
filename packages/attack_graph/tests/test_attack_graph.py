"""
Unit and Integration tests for AttackGraphRepository and Graph Pathfinding.
"""

import os
import sys
import unittest

# Ensure root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from packages.attack_graph.src.in_memory_repository import InMemoryAttackGraphRepository
from packages.attack_graph.src.neo4j_repository import Neo4jAttackGraphRepository
from packages.attack_graph.src.models import (
    GraphEntityType,
    GraphRelationType,
    AttackGraphData
)


class TestAttackGraph(unittest.TestCase):

    def setUp(self):
        self.repo = InMemoryAttackGraphRepository()

    def test_create_entities_and_relationships(self):
        # 1. Create Nodes
        actor = self.repo.create_entity(GraphEntityType.THREAT_ACTOR, "actor-storm-0978", "Storm-0978")
        email = self.repo.create_entity(GraphEntityType.EMAIL, "msg-101", "Executive Compensation EML")
        cve = self.repo.create_entity(GraphEntityType.CVE, "cve-2023-35636", "CVE-2023-35636")
        identity = self.repo.create_entity(GraphEntityType.IDENTITY, "user-cfo", "cfo@enterprise-corp.internal")
        session = self.repo.create_entity(GraphEntityType.SESSION, "sess-owa-88", "OWA Active Session")

        self.assertEqual(actor.label, "ThreatActor")
        self.assertEqual(email.name, "Executive Compensation EML")

        # 2. Create Directed Edges
        self.repo.create_relationship("actor-storm-0978", GraphRelationType.SENDS, "msg-101")
        self.repo.create_relationship("msg-101", GraphRelationType.EXPLOITS, "cve-2023-35636")
        self.repo.create_relationship("msg-101", GraphRelationType.TARGETS, "user-cfo")
        self.repo.create_relationship("user-cfo", GraphRelationType.OWNS, "sess-owa-88")
        self.repo.create_relationship("cve-2023-35636", GraphRelationType.TRIGGERS, "sess-owa-88")

        # 3. Test find_related
        targets = self.repo.find_related("msg-101", GraphRelationType.TARGETS)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].id, "user-cfo")

        # 4. Test Attack Pathfinding (BFS traversal from Threat Actor to Session)
        paths = self.repo.find_attack_paths("actor-storm-0978", "sess-owa-88", max_depth=5)
        self.assertGreaterEqual(len(paths), 1)
        
        first_path = paths[0]
        self.assertEqual(first_path.start_entity, "actor-storm-0978")
        self.assertEqual(first_path.target_entity, "sess-owa-88")
        self.assertIn("Storm-0978", first_path.description)
        self.assertIn("OWA Active Session", first_path.description)

    def test_upsert_observation_atomic_chain(self):
        graph_data = self.repo.upsert_observation(
            email_id="exp-2026-cve35636",
            sender_domain="corporate-updates.net",
            recipient_email="cfo@enterprise-corp.internal",
            target_asset_host="owa.enterprise-corp.internal",
            cve_id="CVE-2023-35636",
            session_id="active-owa-session",
            threat_actor="Storm-0978"
        )

        self.assertIsInstance(graph_data, AttackGraphData)
        node_ids = [n.id for n in graph_data.nodes]
        self.assertIn("exp-2026-cve35636", node_ids)
        self.assertIn("ident-cfo@enterprise-corp.internal", node_ids)
        self.assertIn("cve-cve-2023-35636", node_ids)
        self.assertIn("sess-active-owa-session", node_ids)
        self.assertIn("asset-owa.enterprise-corp.internal", node_ids)

        # Verify export to JSON
        json_export = self.repo.to_graph_json()
        self.assertGreaterEqual(len(json_export.nodes), 6)
        self.assertGreaterEqual(len(json_export.edges), 6)


if __name__ == "__main__":
    unittest.main()
