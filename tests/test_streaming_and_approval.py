import asyncio
import pytest
from apps.agents.streaming_service import SecurityGraphStreamer, AgentEvent
from apps.agents.core.approval_manager import ApprovalManager
from packages.schemas.python.models import (
    SecurityState,
    EmailAttackRepresentation,
    SenderInfo,
    RecipientInfo,
    AuthenticationResults,
    UrlFeature,
    ExploitIndicator
)


def create_sample_state() -> SecurityState:
    ear = EmailAttackRepresentation(
        message_id="msg-stream-test-01",
        timestamp="2026-09-25T14:00:00Z",
        sender=SenderInfo(address="apt@evil-actor.org", domain="evil-actor.org"),
        recipients=[RecipientInfo(address="cfo@victim-corp.com")],
        authentication=AuthenticationResults(spf="pass", dkim="pass", dmarc="pass"),
        headers={"Subject": "Urgent Financial Review [Ticket#8821]"},
        urls=[UrlFeature(url="search-ms:query=payload.exe&crumb=location:\\\\evil-actor.org\\share", domain="evil-actor.org")],
        exploit_indicators=[
            ExploitIndicator(
                indicator_type="MONIKER_LINK",
                evidence="CVE-2024-21413 Moniker detected",
                target_cve="CVE-2024-21413",
                confidence=0.95
            )
        ]
    )

    return SecurityState(
        tenant_id="tenant-stream-demo",
        email_representation=ear.model_dump(),
        autonomy_level=1,
        evidence=[]
    )


@pytest.mark.asyncio
async def test_security_graph_streamer():
    streamer = SecurityGraphStreamer()
    state = create_sample_state()

    events = []
    async for event in streamer.stream_execution(state):
        events.append(event)
        assert isinstance(event, AgentEvent)
        assert event.stage in ("INGESTION", "ANALYSIS", "VULN_RESEARCH", "EXPOSURE", "INVESTIGATION", "RESPONSE")
        sse_line = event.to_sse_line()
        assert sse_line.startswith(f"event: {event.event_type}\n")

    event_types = [e.event_type for e in events]
    assert "stage_start" in event_types
    assert "thought" in event_types
    assert "skill_activated" in event_types
    assert "proposal" in event_types
    assert "complete" in event_types


def test_approval_manager_lifecycle():
    manager = ApprovalManager()
    manager.clear()

    # 1. Register a high-risk proposal
    token = manager.create_pending_approval(
        tenant_id="tenant-stream-demo",
        tool_name="force_password_reset",
        parameters={"user_id": "cfo@victim-corp.com"},
        risk_level="HIGH",
        target_cve="CVE-2024-21413",
        target_identity="cfo@victim-corp.com"
    )

    assert token.startswith("APP-")
    pending = manager.get_pending_approvals("tenant-stream-demo")
    assert len(pending) == 1
    assert pending[0].token == token

    # 2. Authorize and execute
    res = manager.authorize_and_execute(
        tenant_id="tenant-stream-demo",
        token=token,
        approver_email="soc_lead@victim-corp.com",
        comments="Authorized password reset after confirmed NTLM leak"
    )

    assert res["success"] is True
    assert res["executed"] is True
    assert res["tool_name"] == "force_password_reset"
    assert "audit_id" in res

    # 3. Double-execution prevention
    duplicate_res = manager.authorize_and_execute(
        tenant_id="tenant-stream-demo",
        token=token,
        approver_email="soc_lead@victim-corp.com"
    )
    assert duplicate_res["success"] is False
    assert "already been processed" in duplicate_res["error"]


def test_approval_manager_rejection_and_isolation():
    manager = ApprovalManager()
    manager.clear()

    token = manager.create_pending_approval(
        tenant_id="tenant-corp-a",
        tool_name="disable_account",
        parameters={"user_id": "bad_user"}
    )

    # Tenant mismatch test
    mismatch_res = manager.authorize_and_execute(
        tenant_id="tenant-corp-b",
        token=token,
        approver_email="analyst@corp-b.com"
    )
    assert mismatch_res["success"] is False
    assert "Tenant mismatch" in mismatch_res["error"]

    # Reject action
    reject_res = manager.reject_action(
        tenant_id="tenant-corp-a",
        token=token,
        approver_email="analyst@corp-a.com",
        reason="False positive"
    )
    assert reject_res["success"] is True
    assert reject_res["status"] == "REJECTED"
