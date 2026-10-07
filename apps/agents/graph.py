"""
Investigation workflow orchestrator.

Pipeline: Ingestion/MIME parsing -> evidence seeding from the parser -> planner-driven tool loop
-> exposure context -> vulnerability context -> verdict -> report/attack chain -> response proposals.

All evidence is recorded as typed Evidence records in the InvestigationState; the verdict is
computed from those records only (see apps/agents/core/verdict_engine.py).
"""

import logging
import re
import time
import uuid
import email as email_lib
from typing import Dict, Any, Optional, List

from packages.schemas.python.models import SecurityState, ToolProposal
from apps.agents.nodes.ingestion_node import IngestionNode
from apps.agents.nodes.vuln_research_node import VulnResearchNode
from apps.agents.nodes.exposure_node import ExposureNode
from apps.agents.nodes.investigation_node import InvestigationNode
from apps.agents.nodes.response_node import ResponseNode
from apps.agents.core.investigation_state import (
    InvestigationState,
    Artifact as StateArtifact,
    Evidence as StateEvidence,
    ToolExecution as StateToolExecution,
)
from apps.agents.core.investigation_planner import InvestigationPlanner, select_planner
from apps.agents.core.tool_registry import ToolRegistry
from apps.agents.core.event_system import EventStreamManager
from apps.agents.core.verdict_engine import compute_verdict
from apps.agents.skills.skill_registry import SkillRegistry

logger = logging.getLogger("SecurityGraph")

# Parser indicator type -> evidence type consumed by the planner and verdict engine
INDICATOR_EVIDENCE_TYPES = {
    "MONIKER_URI_OBSERVED": "MONIKER_URI",
    "RENDERING_EXPLOIT_URI": "MONIKER_URI",
    "UNC_PATH_OBSERVED": "UNC_PATH",
    "DATA_URI_PAYLOAD_OBSERVED": "DATA_URI",
    "ACTIVE_SCRIPTING": "ACTIVE_SCRIPT",
}

# Outlook MonikerLink (CVE-2024-21413): file:// hyperlink with an exclamation-mark moniker suffix.
MONIKER_LINK_PATTERN = re.compile(r"file:[^\s\"'<>]*![^\s\"'<>]*", re.IGNORECASE)

NETWORK_SCHEMES = ("http://", "https://")


def is_network_url(url: str) -> bool:
    return (url or "").lower().startswith(NETWORK_SCHEMES)


class SecurityGraph:
    def __init__(
        self,
        planner: Optional[InvestigationPlanner] = None,
        tool_registry: Optional[ToolRegistry] = None,
        planner_mode: str = "HYBRID",
        hybrid_policy: str = "RULE_FIRST"
    ):
        self.ingestion_node = IngestionNode()
        self.vuln_research_node = VulnResearchNode()
        self.exposure_node = ExposureNode()
        self.investigation_node = InvestigationNode()
        self.response_node = ResponseNode()
        self.skill_registry = SkillRegistry()
        self.planner_mode = planner_mode
        self.hybrid_policy = hybrid_policy
        self.planner = planner
        self.tool_registry = tool_registry or ToolRegistry.get_instance()

    def run(self, initial_state: SecurityState) -> SecurityState:
        state = initial_state
        logger.info(f"--- [WORKFLOW START] tenant '{state.get('tenant_id')}' ---")

        state = self.ingestion_node.execute(state)
        if state.get("errors"):
            logger.error(f"Ingestion failed: {state['errors']}")
            return state

        state = self._execute_adaptive_investigation(state)
        state = self.exposure_node.execute(state)
        state = self.vuln_research_node.execute(state)

        verdict = compute_verdict(state["investigation_state"])
        state["verdict"] = verdict
        state["investigation_state"].verdict = None  # Verdict is carried separately in the report

        state = self.investigation_node.execute(state)
        state = self.response_node.execute(state)

        logger.info(f"--- [WORKFLOW COMPLETE] verdict={verdict.verdict} severity={verdict.severity} score={verdict.risk_score} ---")
        return state

    # ------------------------------------------------------------------ #
    # Evidence seeding from the deterministic parser
    # ------------------------------------------------------------------ #
    def _seed_parser_evidence(self, inv_state: InvestigationState, rep: Dict[str, Any], state: SecurityState) -> int:
        """Records parser findings as typed evidence; returns the next free evidence index."""
        counter = [101]

        def add(ev_type: str, value: str, source: str, status: str = "OBSERVED", subject: Optional[str] = None,
                metadata: Optional[Dict[str, Any]] = None, confidence: float = 0.95) -> StateEvidence:
            ev = StateEvidence(
                id=f"E-{counter[0]}", evidence_type=ev_type, value=value, source=source,
                status=status, subject=subject, metadata=metadata or {}, confidence=confidence
            )
            inv_state.evidence[ev.id] = ev
            counter[0] += 1
            return ev

        headers = rep.get("headers", {}) or {}
        sender = (rep.get("sender") or {}).get("address") or "unknown"
        recipients = rep.get("recipients") or [{}]
        recipient = recipients[0].get("address") or "unknown"
        subject = headers.get("Subject") or headers.get("subject") or ""
        add("MIME_HEADER", f"From: {sender} | To: {recipient} | Subject: {subject}", "MimeParser",
            metadata={"message_id": rep.get("message_id")})

        auth = rep.get("authentication") or {}
        spf, dkim, dmarc = auth.get("spf", "none"), auth.get("dkim", "none"), auth.get("dmarc", "none")
        if spf in ("fail", "softfail") or dmarc in ("fail", "reject", "quarantine"):
            result = "FAIL"
        elif spf == "none" and dkim == "none" and dmarc == "none":
            result = "UNKNOWN"
        else:
            result = "PASS"
        add("AUTHENTICATION", f"SPF={spf} DKIM={dkim} DMARC={dmarc}", "MimeParser.AuthenticationResults",
            status="UNKNOWN" if result == "UNKNOWN" else "OBSERVED",
            metadata={"result": result, "spf": spf, "dkim": dkim, "dmarc": dmarc,
                      "raw_present": bool(auth.get("auth_results_raw") or headers.get("Authentication-Results"))})
        if result == "UNKNOWN":
            inv_state.add_negative_evidence("authentication_results_absent",
                                            "No Authentication-Results header; sender authentication not verified")

        for u in rep.get("urls", []) or []:
            url = u.get("url", "")
            add("URL_NORMALIZED", url, "HTMLAnalyzer", subject=url,
                metadata={"url": url, "domain": u.get("domain"), "is_mismatched": bool(u.get("is_mismatched")),
                          "display_text": u.get("display_text"), "is_network": is_network_url(url)})
            if u.get("is_mismatched"):
                add("DECEPTIVE_LINK", f"Link text '{(u.get('display_text') or '')[:80]}' points to {url}", "HTMLAnalyzer",
                    subject=url, metadata={"url": url, "display_text": u.get("display_text")})

        seen_types = set()
        for ind in rep.get("exploit_indicators", []) or []:
            itype = ind.get("indicator_type", "")
            ev_type = "UNICODE_ANOMALY" if itype.startswith("UNICODE_") else INDICATOR_EVIDENCE_TYPES.get(itype)
            if not ev_type:
                continue
            ev = add(ev_type, ind.get("evidence", itype), "MimeParser", metadata={"indicator_type": itype},
                     confidence=float(ind.get("confidence") or 0.9))
            state.setdefault("evidence", []).append({"stage": "STATIC_ANALYSIS", "type": itype, "detail": ind.get("evidence", ""), "evidence_id": ev.id})
            seen_types.add(ev_type)
            if ind.get("target_cve"):
                add("CVE_CANDIDATE", f"Indicator references {ind['target_cve']}", "MimeParser",
                    status="INFERRED", metadata={"cve_id": ind["target_cve"]})

        body = rep.get("body") or {}
        haystack = " ".join(filter(None, [body.get("text_html"), body.get("text_plain")] + [u.get("url", "") for u in rep.get("urls", []) or []]))
        if MONIKER_LINK_PATTERN.search(haystack) and not any(e.evidence_type == "CVE_CANDIDATE" for e in inv_state.evidence.values()):
            add("CVE_CANDIDATE", "file:// hyperlink with '!' moniker suffix (MonikerLink pattern)", "MimeParser",
                status="INFERRED", metadata={"cve_id": "CVE-2024-21413"})

        for feat in rep.get("behavioral_features", []) or []:
            state.setdefault("evidence", []).append({"stage": "INGESTION_BEHAVIORAL", "type": "BEHAVIORAL_FEATURE", "detail": feat})

        if "UNICODE_ANOMALY" not in seen_types:
            inv_state.add_negative_evidence("no_parser_unicode_anomaly", "Parser found no bidi/zero-width/tag/confusable characters")
        if not (rep.get("urls") or []):
            inv_state.add_negative_evidence("no_url", "No URLs found in email body or headers")

        return counter[0]

    # ------------------------------------------------------------------ #
    # Planner-driven tool loop
    # ------------------------------------------------------------------ #
    def _execute_adaptive_investigation(self, state: SecurityState) -> SecurityState:
        raw_eml = state.get("raw_eml", b"")
        rep = state.get("email_representation", {}) or {}
        tenant_id = state.get("tenant_id", "tenant-default")
        incident_id = state.get("incident_id") or state.get("workflow_id") or f"wf-{uuid.uuid4().hex[:6]}"
        agent_run_id = state.get("agent_run_id") or f"run-{uuid.uuid4().hex[:8]}"
        autonomy_level = state.get("autonomy_level", 1)

        parsed = email_lib.message_from_bytes(raw_eml) if raw_eml else None
        attachments: List[Dict[str, Any]] = []
        if parsed:
            for part in parsed.walk():
                fn = part.get_filename()
                cd = str(part.get("Content-Disposition", ""))
                if fn or "attachment" in cd.lower():
                    payload = part.get_payload(decode=True) or b""
                    if payload:
                        attachments.append({"filename": fn or "unnamed_attachment", "payload": payload, "mime": part.get_content_type()})

        headers = rep.get("headers", {}) or {}
        body = rep.get("body") or {}
        body_plain = body.get("text_plain") or ""
        body_html = body.get("text_html") or ""
        subject_line = headers.get("Subject") or headers.get("subject") or ""
        urls = rep.get("urls", []) or []
        network_urls = [u.get("url", "") for u in urls if is_network_url(u.get("url", ""))]
        sender = rep.get("sender") or {}
        recipient_addr = ((rep.get("recipients") or [{}])[0].get("address")) or ""

        inv_state = InvestigationState(incident_id=incident_id, tenant_id=tenant_id, autonomy_level=autonomy_level,
                                       raw_eml=raw_eml, remaining_budget_steps=15)
        inv_state.artifacts.append(StateArtifact(artifact_type="EML_RAW", raw_data=len(raw_eml), location="RAW_EML"))
        inv_state.artifacts.append(StateArtifact(artifact_type="MIME_HEADER", raw_data=headers, location="HEADERS"))
        if body_plain:
            inv_state.artifacts.append(StateArtifact(artifact_type="BODY_PLAIN", raw_data=body_plain, location="BODY: text/plain"))
        if body_html:
            inv_state.artifacts.append(StateArtifact(artifact_type="BODY_HTML", raw_data=body_html, location="BODY: text/html"))
        for u in urls:
            inv_state.artifacts.append(StateArtifact(artifact_type="URL_STRING", raw_data=u.get("url", ""), location="BODY_URL"))
        for att in attachments:
            inv_state.artifacts.append(StateArtifact(artifact_type="ATTACHMENT_PAYLOAD", raw_data=att, location=f"ATTACHMENT: {att['filename']}"))
        if not attachments:
            inv_state.add_negative_evidence("no_attachment", "No MIME attachments found in message container")

        e_idx = self._seed_parser_evidence(inv_state, rep, state)

        try:
            from packages.schemas.python.models import EmailAttackRepresentation
            state["activated_skills"] = [s.name for s in self.skill_registry.match_skills(EmailAttackRepresentation(**rep))]
        except Exception:
            state["activated_skills"] = []

        active_planner = self.planner or select_planner(
            mode=state.get("planner_mode") or self.planner_mode or "HYBRID",
            hybrid_policy=state.get("hybrid_policy") or self.hybrid_policy or "RULE_FIRST",
            tier_risk_score=state.get("risk_score"),
        )
        inv_state.planner_requested = (state.get("planner_mode") or self.planner_mode or "HYBRID").upper()
        inv_state.planner_engine = inv_state.planner_requested

        available_tools = self.tool_registry.get_tool_definitions()
        permissions = ["email.parse", "threat_intel.query", "attachment.inspect", "sandbox.browser_execute", "network.dns_lookup", "telemetry.query"]
        event_manager = EventStreamManager.get_instance()

        def new_evidence(**kw) -> StateEvidence:
            nonlocal e_idx
            ev = StateEvidence(id=f"E-{e_idx}", **kw)
            inv_state.evidence[ev.id] = ev
            e_idx += 1
            return ev

        while inv_state.remaining_budget_steps > 0:
            decision = active_planner.propose_next_action(inv_state, available_tools, permissions)
            inv_state.decisions.append(decision)
            inv_state.remaining_budget_steps -= 1
            event_manager.publish_event(
                investigation_id=incident_id, agent_run_id=agent_run_id, event_type="agent.planner.selected",
                message=f"Planner ({decision.planner_type}) selected action: {decision.action} ({decision.tool_name or decision.stop_reason or ''})",
                status="SUCCESS", decision_id=decision.decision_id, tool=decision.tool_name,
                data={"planner_type": decision.planner_type, "engine_type": decision.engine_type, "action": decision.action,
                      "tool": decision.tool_name, "arbitration": decision.arbitration,
                      "expected_gain": decision.expected_information_gain, "confidence": decision.confidence}
            )

            if decision.action != "RUN_TOOL":
                inv_state.is_complete = True
                inv_state.stop_reason = decision.stop_reason or decision.action
                break

            tool_name = decision.tool_name
            target_url = network_urls[0] if network_urls else ""
            if tool_name == "UnicodeAnalyzer":
                params = {"text": f"{subject_line}\n{body_plain}\n{body_html}", "location": "EMAIL_PAYLOAD"}
            elif tool_name in ("threat_intel_lookup", "ThreatIntelFeeds"):
                params = {"indicator_type": "url", "indicator_value": target_url}
            elif tool_name in ("url_sandbox_detonation", "UrlSandboxRunner"):
                params = {"url": target_url}
            elif tool_name in ("inspect_attachment", "AttachmentAnalyzer"):
                att0 = attachments[0] if attachments else {"filename": "", "payload": b"", "mime": ""}
                params = {"filename": att0["filename"], "payload_bytes": att0["payload"], "declared_mime": att0.get("mime", "")}
            elif tool_name == "dns_spf_dmarc_recon":
                params = {"domain": sender.get("domain", "")}
            elif tool_name == "query_sender_history":
                params = {"sender_email": sender.get("address", ""), "recipient_email": recipient_addr,
                          "sender_domain": sender.get("domain", ""), "tenant_id": tenant_id}
            elif tool_name == "CisaKevCorrelator":
                cand = inv_state.get_latest_evidence("CVE_CANDIDATE")
                params = {"cve_id": cand.metadata.get("cve_id") if cand else ""}
            else:
                params = {}

            t0 = time.perf_counter()
            res = self.tool_registry.execute_proposal(
                tenant_id=tenant_id,
                proposal=ToolProposal(tool_name=tool_name, parameters=params, reasoning=decision.rationale),
                autonomy_level=autonomy_level, incident_id=incident_id,
            )
            dur_ms = max(0.01, round((time.perf_counter() - t0) * 1000.0, 2))
            out = res.output or {}
            produced: List[str] = []
            ok = res.success and res.executed

            if not ok:
                pass
            elif tool_name == "UnicodeAnalyzer":
                if out.get("has_anomalies"):
                    if not inv_state.get_latest_evidence("UNICODE_ANOMALY"):
                        produced.append(new_evidence(evidence_type="UNICODE_ANOMALY", source="UnicodeAnalyzer",
                                                     value="; ".join(out.get("anomalies", [])[:3]) or "Unicode anomaly detected",
                                                     metadata={"anomalies": out.get("anomalies", [])}).id)
                else:
                    inv_state.add_negative_evidence("no_suspicious_unicode", "UnicodeAnalyzer found no tags/RTLO/zero-width characters")
            elif tool_name in ("threat_intel_lookup", "ThreatIntelFeeds"):
                is_mal = bool(out.get("is_malicious", False))
                feeds_ok = bool(out.get("feeds_succeeded"))
                status = "MALICIOUS" if is_mal else ("NOT_LISTED" if feeds_ok else "UNAVAILABLE")
                ev = new_evidence(evidence_type="URL_REPUTATION", source="ThreatIntelFeeds", subject=target_url,
                                  value=f"Threat intel reputation for {target_url}: {status}",
                                  status="OBSERVED" if feeds_ok or is_mal else "UNKNOWN",
                                  metadata={"url": target_url, "reputation": status, "is_malicious": is_mal, "details": out})
                produced.append(ev.id)
                if not is_mal:
                    inv_state.add_negative_evidence("no_known_malicious_reputation" if feeds_ok else "reputation_unavailable",
                                                    f"Reputation feeds {'did not list' if feeds_ok else 'could not assess'} {target_url}")
            elif tool_name in ("url_sandbox_detonation", "UrlSandboxRunner"):
                verdict = str(out.get("verdict", "UNKNOWN"))
                ev = new_evidence(evidence_type="BEHAVIORAL_SANDBOX", source="UrlSandboxRunner", subject=target_url,
                                  value=f"Static URL analysis verdict {verdict} (risk {out.get('risk_score', 0)}/100)",
                                  metadata={"url": target_url, "verdict": verdict, "risk_score": out.get("risk_score", 0),
                                            "is_benign": verdict == "CLEAN", "evidence": out.get("evidence", []),
                                            "final_destination_url": out.get("final_destination_url"),
                                            "execution_mode": "STATIC_HTTP_FETCH"})
                produced.append(ev.id)
                rep_ev = inv_state.get_latest_evidence("URL_REPUTATION", subject=target_url)
                if verdict in ("MALICIOUS", "SUSPICIOUS") and rep_ev and not rep_ev.metadata.get("is_malicious"):
                    inv_state.add_contradiction("Reputation feeds did not list the URL but static analysis found it suspicious",
                                                [rep_ev.id, ev.id], impact="HIGH")
            elif tool_name in ("inspect_attachment", "AttachmentAnalyzer"):
                ev = new_evidence(evidence_type="ATTACHMENT_ANALYSIS", source="AttachmentAnalyzer", subject=params.get("filename"),
                                  value=f"Attachment '{params.get('filename')}' ({out.get('magic_description', out.get('container_type', 'unknown'))}) risk {out.get('risk_score', 0)}",
                                  metadata={"risk_score": out.get("risk_score", 0), "sha256": out.get("sha256"),
                                            "risk_factors": out.get("risk_factors", []), "container_type": out.get("container_type")})
                produced.append(ev.id)
                if out.get("motw_evasion_detected") or out.get("motw_evasion"):
                    produced.append(new_evidence(evidence_type="ATTACHMENT_PE", source="AttachmentAnalyzer.IsoParser",
                                                 subject=params.get("filename"),
                                                 value="Mark-of-the-Web evasion container with embedded executable payload").id)
            elif tool_name == "query_sender_history":
                produced.append(new_evidence(evidence_type="HISTORICAL_COMMUNICATION", source="TelemetryServer",
                                             value=f"Sender history: count={out.get('historical_email_count', 0)}, first-time={out.get('is_first_time_sender')}",
                                             metadata=out).id)
            elif tool_name == "dns_spf_dmarc_recon":
                produced.append(new_evidence(evidence_type="DNS_RECON", source="DnsServer",
                                             value=f"DNS recon: SPF={out.get('has_spf')}, DMARC={out.get('has_dmarc')}",
                                             metadata=out).id)
            elif tool_name == "CisaKevCorrelator":
                produced.append(new_evidence(evidence_type="CISA_KEV_MATCH", source="CisaKevCorrelator",
                                             value=f"{params.get('cve_id')}: {'listed' if out.get('is_in_kev') else 'not listed'} in CISA KEV ({out.get('provenance', {}).get('catalog_version')})",
                                             metadata={"cve_id": params.get("cve_id"), "is_in_kev": bool(out.get("is_in_kev")), "provenance": out.get("provenance")}).id)

            inv_state.executed_tools.append(StateToolExecution(
                tool_name=tool_name, status="COMPLETED" if ok else "FAILED", duration_ms=dur_ms,
                input_params={k: (f"<{len(v)} bytes>" if isinstance(v, (bytes, bytearray)) else v) for k, v in params.items()},
                output_summary=str(out)[:500], error=res.error, produced_evidence_ids=produced,
            ))
            event_manager.publish_event(
                investigation_id=incident_id, agent_run_id=agent_run_id, event_type="agent.tool.executed",
                message=f"Executed tool {tool_name} in {dur_ms}ms ({'COMPLETED' if ok else 'FAILED'})",
                status="SUCCESS" if ok else "FAILED", tool=tool_name, duration=dur_ms / 1000.0,
                evidence_ids=produced, error=res.error, data={"duration_ms": dur_ms}
            )
            for eid in produced:
                ev = inv_state.evidence[eid]
                event_manager.publish_event(
                    investigation_id=incident_id, agent_run_id=agent_run_id, event_type="agent.evidence.created",
                    message=f"Generated evidence {eid}: {ev.evidence_type} ({ev.source})", status="SUCCESS",
                    tool=tool_name, evidence_ids=[eid], data={"evidence_id": eid, "type": ev.evidence_type, "value": ev.value}
                )

        state["planner_requested"] = inv_state.planner_requested
        state["planner_used"] = inv_state.planner_used
        state["fallback_reason"] = inv_state.fallback_reason
        state["investigation_state"] = inv_state
        return state
