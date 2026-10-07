"""Reasoning chains on every decision, and live streaming of background investigations."""

import json

import pytest
from fastapi.testclient import TestClient

from apps.server import app
from apps.agents.core.agent_builder import PlannerSettings, save_planner_settings
from apps.agents.core.llm_gateway import LLMGateway
from apps.agents.core.security_principal import create_principal_token
from apps.agents.investigation_service import InvestigationService

PHISH = "tests/fixtures/corpus/04_phish_spf_fail_url.eml"


def _headers(tenant="tenant-live"):
    return {"Authorization": "Bearer " + create_principal_token("alice", tenant, ["SOC_ANALYST"])}


def _events(client, incident_id, headers):
    out, current = [], None
    with client.stream("GET", f"/api/v1/investigations/{incident_id}/events", headers=headers) as r:
        assert r.status_code == 200
        for line in r.iter_lines():
            if line.startswith("data:"):
                out.append(json.loads(line[5:]))
    return out


def test_background_investigation_streams_thinking_and_reasoned_decisions():
    client = TestClient(app)
    with open(PHISH, "rb") as f:
        r = client.post("/api/v1/investigations", headers=_headers(), files={"file": ("p.eml", f.read())})
    assert r.status_code == 202
    iid = r.json()["incident_id"]
    events = _events(client, iid, _headers())
    types = [e["event_type"] for e in events]
    assert types[0] == "agent.started" and types[-1] == "agent.completed"
    assert "agent.thinking" in types and "agent.tool.executed" in types
    decisions = [e for e in events if e["event_type"] == "agent.planner.selected"]
    assert decisions and all(d["data"]["reasoning_steps"] for d in decisions)
    assert any("Chose ThreatIntelFeeds" in s for d in decisions for s in d["data"]["reasoning_steps"])
    inc = client.get(f"/api/v1/incidents/{iid}", headers=_headers()).json()
    assert inc["severity"] == "HIGH"
    assert all(d["reasoning_steps"] for d in inc["decision_trace"])


def test_other_tenant_cannot_stream_a_background_investigation():
    client = TestClient(app)
    with open(PHISH, "rb") as f:
        iid = client.post("/api/v1/investigations", headers=_headers(), files={"file": ("p.eml", f.read())}).json()["incident_id"]
    assert client.get(f"/api/v1/investigations/{iid}/events", headers=_headers("tenant-other")).status_code == 404
    _events(client, iid, _headers())  # drain


def test_llm_thought_text_and_overrides_are_recorded_per_decision(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test-stub")
    replies = [
        {"content": json.dumps({"decision": "RUN_TOOL", "tool": "ThreatIntelFeeds", "question_id": "Q-03",
                                "rationale_summary": "Check the link's reputation first."}),
         "reasoning": "The sender failed SPF and the link text mismatches. Reputation is the cheapest signal."},
        {"content": json.dumps({"decision": "STOP", "rationale_summary": "Looks bad enough."}),
         "reasoning": "I think we are done."},
    ]

    def fake(self, prompt, system_prompt="", model_id=None, temperature=0.1, json_mode=False):
        r = replies.pop(0) if replies else {"content": json.dumps({"decision": "STOP"}), "reasoning": None}
        return {**r, "status": "COMPLETED", "model_used": "stub-model", "actual_call": True,
                "tokens_prompt": 10, "tokens_completion": 5}

    monkeypatch.setattr(LLMGateway, "generate_completion", fake)
    save_planner_settings("tenant-reason", PlannerSettings(planner_mode="LLM"))
    with open(PHISH, "rb") as f:
        inc = InvestigationService().run_investigation("tenant-reason", f.read())
    first, second = inc.decision_trace[0], inc.decision_trace[1]
    assert first.planner_type == "LLM" and "cheapest signal" in first.reasoning_trace
    assert any("Check the link's reputation first." in s for s in first.reasoning_steps)
    # The early STOP is overridden because questions were still open; the decision says why.
    assert second.planner_type == "RULE"
    assert second.override_reason.startswith("LLM STOP rejected")
    assert second.llm_proposal["decision"] == "STOP"
    assert second.reasoning_steps[0].startswith("LLM not followed")


def test_matched_playbooks_are_recorded_and_given_to_the_llm(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test-stub")
    prompts = []

    def fake(self, prompt, system_prompt="", model_id=None, temperature=0.1, json_mode=False):
        prompts.append(prompt)
        return {"content": json.dumps({"decision": "STOP"}), "status": "COMPLETED", "model_used": "stub",
                "actual_call": True, "tokens_prompt": 1, "tokens_completion": 1}

    monkeypatch.setattr(LLMGateway, "generate_completion", fake)
    save_planner_settings("tenant-skills", PlannerSettings(planner_mode="LLM"))
    with open("packages/email_parser/samples/synthetic_cve_2023_35636_rendering_exploit.eml", "rb") as f:
        inc = InvestigationService().run_investigation("tenant-skills", f.read())
    assert "moniker_exploit_triage" in inc.activated_skills
    assert "[SKILL: MONIKER_EXPLOIT_TRIAGE]" in prompts[0]
