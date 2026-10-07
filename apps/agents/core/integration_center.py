"""
Integration status center.

Integrations are configured through environment variables (or a secrets manager that injects
them) — the same variables the tools read at execution time. This module reports, read-only,
which integrations are configured and, where it is safe to do so, probes them. Response
connectors are never probed because a probe would perform a real action; they report
CONFIGURED_UNVERIFIED until a real dispatch succeeds.
"""

import json
import os
import time
from enum import Enum
from typing import Any, Dict, List, Optional

import requests
from pydantic import BaseModel, Field


class IntegrationStatus(str, Enum):
    OPERATIONAL = "OPERATIONAL"
    CONFIGURED_UNVERIFIED = "CONFIGURED_UNVERIFIED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    UNAVAILABLE = "UNAVAILABLE"
    DEGRADED = "DEGRADED"


class IntegrationRecord(BaseModel):
    integration_id: str
    name: str
    category: str  # THREAT_INTEL, LLM, RESPONSE, LOCAL_DATA
    used_by: List[str] = Field(default_factory=list)
    env_vars: List[str] = Field(default_factory=list)
    status: IntegrationStatus = IntegrationStatus.NOT_CONFIGURED
    health_message: str = ""
    last_health_check: Optional[str] = None
    latency_ms: Optional[float] = None


def _any_env(*names: str) -> Optional[str]:
    for n in names:
        v = os.getenv(n, "").strip()
        if v:
            return v
    return None


# (id, name, category, tools, url env vars)
RESPONSE_CONNECTORS = [
    ("mail-gateway", "Mail gateway quarantine", "RESPONSE", ["quarantine_email"], ["MAIL_GATEWAY_URL", "M365_GRAPH_ENDPOINT"]),
    ("idp-sessions", "IdP session revocation", "RESPONSE", ["revoke_session"], ["IDP_API_URL"]),
    ("idp-accounts", "Account disable", "RESPONSE", ["disable_account"], ["ACTIVE_DIRECTORY_URL", "IDP_ACCOUNT_URL"]),
    ("idp-password", "Forced password reset", "RESPONSE", ["force_password_reset"], ["IDP_PASSWORD_RESET_URL"]),
    ("gateway-block", "Sender block list", "RESPONSE", ["block_sender"], ["GATEWAY_BLOCK_URL", "M365_BLOCKLIST_URL"]),
    ("firewall-block", "IOC block (firewall/EDR)", "RESPONSE", ["block_ioc"], ["FIREWALL_API_URL", "EDR_BLOCK_URL"]),
    ("mailbox-search", "Historical mailbox search", "RESPONSE", ["search_mailbox_history"], ["MAILBOX_SEARCH_URL"]),
    ("soc-ticket", "SOC ticketing webhook", "RESPONSE", ["create_soc_ticket"], ["SOC_TICKET_WEBHOOK_URL"]),
]


class IntegrationManager:
    _instance: Optional["IntegrationManager"] = None

    @classmethod
    def get_instance(cls) -> "IntegrationManager":
        if cls._instance is None:
            cls._instance = IntegrationManager()
        return cls._instance

    def list_integrations(self, probe: bool = False) -> List[Dict[str, Any]]:
        records = [self._urlhaus(probe), self._quad9(probe), self._kev(), self._llm()]
        for cid, name, cat, tools, envs in RESPONSE_CONNECTORS:
            configured = _any_env(*envs)
            records.append(IntegrationRecord(
                integration_id=cid, name=name, category=cat, used_by=tools, env_vars=envs,
                status=IntegrationStatus.CONFIGURED_UNVERIFIED if configured else IntegrationStatus.NOT_CONFIGURED,
                health_message=("Endpoint configured; not probed because a probe would perform a real action."
                                if configured else f"Set {' or '.join(envs)} to enable."),
            ))
        return [r.model_dump() for r in records]

    def get(self, integration_id: str, probe: bool = True) -> Dict[str, Any]:
        for r in self.list_integrations(probe=probe):
            if r["integration_id"] == integration_id:
                return r
        raise KeyError(integration_id)

    # --- probes ------------------------------------------------------------
    @staticmethod
    def _timed(rec: IntegrationRecord, fn) -> IntegrationRecord:
        start = time.time()
        rec.last_health_check = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        try:
            fn(rec)
        except Exception as exc:
            rec.status = IntegrationStatus.UNAVAILABLE
            rec.health_message = f"Probe failed: {exc.__class__.__name__}: {str(exc)[:160]}"
        rec.latency_ms = round((time.time() - start) * 1000.0, 1)
        return rec

    def _urlhaus(self, probe: bool) -> IntegrationRecord:
        rec = IntegrationRecord(integration_id="urlhaus", name="URLhaus", category="THREAT_INTEL",
                                used_by=["ThreatIntelFeeds"], env_vars=["URLHAUS_AUTH_KEY"])
        key = _any_env("URLHAUS_AUTH_KEY")
        if not key:
            rec.health_message = "Set URLHAUS_AUTH_KEY (URLhaus requires an Auth-Key)."
            return rec
        rec.status = IntegrationStatus.CONFIGURED_UNVERIFIED
        if not probe:
            return rec

        def run(r: IntegrationRecord):
            resp = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": "https://example.com/"},
                                 headers={"Auth-Key": key}, timeout=5)
            ok = resp.status_code == 200 and resp.json().get("query_status") in ("ok", "no_results")
            r.status = IntegrationStatus.OPERATIONAL if ok else IntegrationStatus.UNAVAILABLE
            r.health_message = f"HTTP {resp.status_code}" + ("" if ok else f": {resp.text[:120]}")
        return self._timed(rec, run)

    def _quad9(self, probe: bool) -> IntegrationRecord:
        rec = IntegrationRecord(integration_id="quad9", name="Quad9 threat-blocking DNS", category="THREAT_INTEL",
                                used_by=["ThreatIntelFeeds"], status=IntegrationStatus.CONFIGURED_UNVERIFIED,
                                health_message="No credentials required.")
        if not probe:
            return rec

        def run(r: IntegrationRecord):
            from packages.threat_intel.src.free_feeds import dns_udp_query
            rcode, _ = dns_udp_query("9.9.9.9", "example.com", timeout=3.0)
            r.status = IntegrationStatus.OPERATIONAL if rcode == 0 else IntegrationStatus.DEGRADED
            r.health_message = f"Quad9 9.9.9.9 answered (rcode {rcode})"
        return self._timed(rec, run)

    def _kev(self) -> IntegrationRecord:
        path = os.path.join(os.path.dirname(__file__), "data", "known_exploited_vulnerabilities.json")
        rec = IntegrationRecord(integration_id="cisa-kev", name="CISA KEV (bundled subset)", category="LOCAL_DATA",
                                used_by=["CisaKevCorrelator"])
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            rec.status = IntegrationStatus.OPERATIONAL
            rec.health_message = (f"{len(data.get('vulnerabilities', []))} entries from catalog version "
                                  f"{data.get('catalogVersion')} (refresh with scripts/refresh_kev.py)")
        except Exception as exc:
            rec.status = IntegrationStatus.UNAVAILABLE
            rec.health_message = f"Dataset unreadable: {exc}"
        return rec

    def _llm(self) -> IntegrationRecord:
        configured = _any_env("OPENROUTER_API_KEY")
        return IntegrationRecord(
            integration_id="openrouter", name="OpenRouter LLM planner", category="LLM",
            used_by=["LLMPlanner", "HybridPlanner"], env_vars=["OPENROUTER_API_KEY", "OPENROUTER_MODEL"],
            status=IntegrationStatus.CONFIGURED_UNVERIFIED if configured else IntegrationStatus.NOT_CONFIGURED,
            health_message=(f"Model {os.getenv('OPENROUTER_MODEL', 'openrouter/free')}" if configured
                            else "Not configured; the deterministic rule planner is used."),
        )
