"""
Live LLM planner test against OpenRouter (free models only).

Opt-in: skipped unless OPENROUTER_API_KEY is set. Never commit a key; export it in your shell:
    OPENROUTER_API_KEY=... OPENROUTER_MODEL=nvidia/nemotron-3-super-120b-a12b:free pytest -m llm_live -s
Uses about 6 requests (free-tier daily quotas are small).
"""

import os

import pytest

from apps.agents.core.agent_builder import PlannerSettings, save_planner_settings
from apps.agents.core.llm_gateway import is_free_model
from apps.agents.investigation_service import InvestigationService

pytestmark = [
    pytest.mark.network,
    pytest.mark.llm_live,
    pytest.mark.skipif(not os.getenv("OPENROUTER_API_KEY"), reason="OPENROUTER_API_KEY not set"),
]

PHISH = "tests/fixtures/corpus/04_phish_spf_fail_url.eml"
BENIGN = "tests/fixtures/corpus/01_benign_auth_pass.eml"


@pytest.fixture(autouse=True)
def _free_model_only():
    model = os.getenv("OPENROUTER_MODEL", "openrouter/free")
    assert is_free_model(model), f"Live tests only run on free models, got {model}"
    os.environ["OPENROUTER_FREE_MODELS_ONLY"] = "true"


def _investigate(path, tenant):
    save_planner_settings(tenant, PlannerSettings(planner_mode="LLM", hybrid_arbitration_policy="LLM_FIRST"))
    with open(path, "rb") as f:
        return InvestigationService().run_investigation(tenant, f.read())


def _report(inc):
    calls = inc.forensic_audit.llm_calls
    print(f"\n{inc.subject}: {inc.severity} {inc.overall_risk_score} tools={[t.tool_name for t in inc.tool_executions]}")
    for c in calls:
        print(f"  {c.get('model')} {c.get('status')} {c.get('latency_ms')}ms")
    return calls


def test_real_llm_plans_a_phishing_investigation():
    inc = _investigate(PHISH, "tenant-live-phish")
    calls = _report(inc)
    if any(c.get("status") == "RATE_LIMITED" for c in calls):
        pytest.skip("Provider rate-limited the free model; rules completed the investigation")
    assert any(c.get("status") == "COMPLETED" for c in calls), "no successful LLM call"
    assert {"ThreatIntelFeeds", "UrlSandboxRunner"} <= {t.tool_name for t in inc.tool_executions}
    assert inc.severity == "HIGH" and any(p["tool_name"] == "quarantine_email" for p in inc.pending_approvals)
    assert inc.telemetry.tokens_input > 0


def test_real_llm_leaves_benign_mail_benign():
    inc = _investigate(BENIGN, "tenant-live-benign")
    _report(inc)
    assert inc.severity == "LOW" and inc.pending_approvals == []
