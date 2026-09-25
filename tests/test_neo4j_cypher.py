import pytest
from packages.attack_graph.src.neo4j_repository import Neo4jAttackGraphRepository
from packages.attack_graph.src.models import GraphEntityType, GraphRelationType


def test_neo4j_repository_initialization_and_fallback():
    # Instantiate with dummy offline credentials
    repo = Neo4jAttackGraphRepository(uri="bolt://127.0.0.1:9999", user="neo4j", password="bad")
    assert repo.is_connected is False

    # Verify fallback handles entity creation safely
    node = repo.create_entity(
        entity_type=GraphEntityType.THREAT_ACTOR,
        entity_id="actor-storm-0978",
        name="Storm-0978",
        properties={"origin": "RU"}
    )
    assert node.id == "actor-storm-0978"
    assert node.name == "Storm-0978"
    assert node.label == "ThreatActor"

    # Verify relationship creation
    email_node = repo.create_entity(
        entity_type=GraphEntityType.EMAIL,
        entity_id="email-test-01",
        name="email-test-01"
    )
    edge = repo.create_relationship(
        from_id=node.id,
        relation_type=GraphRelationType.DELIVERS,
        to_id=email_node.id
    )
    assert edge.source == "actor-storm-0978"
    assert edge.target == "email-test-01"
    assert edge.relation == "DELIVERS"


def test_neo4j_repository_upsert_and_pathfinding():
    repo = Neo4jAttackGraphRepository(uri="bolt://127.0.0.1:9999", user="neo4j", password="bad")
    
    # Test atomic observation upsert
    graph = repo.upsert_observation(
        email_id="msg-cve-2024-21413",
        sender_domain="evil-apt.com",
        recipient_email="finance_director@corp.internal",
        target_asset_host="mail.corp.internal",
        cve_id="CVE-2024-21413",
        session_id="active-sess-99",
        threat_actor="APT-28"
    )

    node_ids = [n.id for n in graph.nodes]
    assert "actor-apt-28" in node_ids
    assert "cve-cve-2024-21413" in node_ids
    assert "asset-mail.corp.internal" in node_ids
    assert "sess-active-sess-99" in node_ids

    # Test pathfinding from ThreatActor to Session
    paths = repo.find_attack_paths("actor-apt-28", "sess-active-sess-99", max_depth=6)
    assert len(paths) >= 1
    shortest = paths[0]
    assert shortest.steps[0] == "actor-apt-28"
    assert shortest.steps[-1] == "sess-active-sess-99"
