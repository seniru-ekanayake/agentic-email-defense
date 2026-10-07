"""Durable persistence across restarts and SSE replay/termination."""

import asyncio

from fastapi.testclient import TestClient

from apps.server import app
from apps.agents.core.durable_storage import DurableStorage
from apps.agents.core.event_system import EventStreamManager
from apps.agents.core.security_principal import create_principal_token
from apps.agents.investigation_service import InvestigationService

SAMPLE = "packages/email_parser/samples/synthetic_cve_2023_35636_rendering_exploit.eml"
HEADERS = {"Authorization": "Bearer " + create_principal_token("alice", "tenant-persist", ["SOC_ANALYST"])}


def _investigate():
    with open(SAMPLE, "rb") as f:
        return InvestigationService().run_investigation("tenant-persist", f.read())


def test_incident_survives_a_fresh_storage_and_service():
    inc = _investigate()
    fresh_storage = DurableStorage(DurableStorage.get_instance().db_path)  # new connection, as after a restart
    assert fresh_storage.get_incident(inc.incident_id)["incident_id"] == inc.incident_id
    assert len(fresh_storage.get_evidence_for_incident(inc.incident_id)) == len(inc.evidence_items)
    token = inc.pending_approvals[0]["approval_token"]
    assert fresh_storage.get_approval_token(token)["status"] == "PENDING"
    assert fresh_storage.load_investigation_state(inc.incident_id) is not None


def test_status_changes_are_persisted():
    inc = _investigate()
    client = TestClient(app)
    r = client.post(f"/api/v1/incidents/{inc.incident_id}/status", headers=HEADERS, json={"status": "FALSE_POSITIVE"})
    assert r.status_code == 200
    assert DurableStorage.get_instance().get_incident(inc.incident_id)["status"] == "FALSE_POSITIVE"


def test_events_replay_from_storage_after_buffer_is_released():
    inc = _investigate()
    manager = EventStreamManager.get_instance()
    assert inc.incident_id not in manager._investigation_events  # released after persistence
    events = manager.get_events(inc.incident_id)
    types = [e.event_type for e in events]
    assert types[0] == "agent.started" and "agent.completed" in types
    assert "agent.proposal.created" in types


def test_sse_stream_replays_and_closes_for_a_finished_investigation():
    inc = _investigate()
    client = TestClient(app)
    with client.stream("GET", f"/api/v1/investigations/{inc.incident_id}/events", headers=HEADERS) as r:
        assert r.status_code == 200
        body = "".join(r.iter_text())  # returns only because the server ends the stream
    assert "event: agent.started" in body
    assert "event: agent.proposal.created" in body
    assert body.rstrip().count("event: agent.completed") == 1


def test_subscriber_receives_live_events_then_terminates():
    manager = EventStreamManager.get_instance()

    async def scenario():
        received = []

        async def consume():
            async for ev in manager.subscribe("live-test", heartbeat_seconds=0.05, max_seconds=5):
                if ev is not None:
                    received.append(ev.event_type)

        task = asyncio.create_task(consume())
        await asyncio.sleep(0.05)
        manager.publish_event(investigation_id="live-test", agent_run_id="r", event_type="agent.started", message="start")
        manager.publish_event(investigation_id="live-test", agent_run_id="r", event_type="agent.completed", message="done")
        await asyncio.wait_for(task, timeout=2)
        return received

    assert asyncio.run(scenario()) == ["agent.started", "agent.completed"]
