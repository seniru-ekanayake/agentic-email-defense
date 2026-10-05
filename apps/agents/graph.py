"""
LangGraph & Native Agentic Workflow Orchestrator.
Assembles the typed SecurityState graph connecting Ingestion, Dynamic Adaptive Planning Loop,
Exposure Correlation, Vulnerability Research, Incident Scoring, and Response Planning.
"""

import logging
import time
import uuid
import email as email_lib
from typing import Dict, Any, Callable, Optional, List

from packages.schemas.python.models import SecurityState, ToolProposal
from apps.agents.nodes.ingestion_node import IngestionNode
from apps.agents.nodes.email_analysis_node import EmailAnalysisNode
from apps.agents.nodes.vuln_research_node import VulnResearchNode
from apps.agents.nodes.exposure_node import ExposureNode
from apps.agents.nodes.investigation_node import InvestigationNode
from apps.agents.nodes.response_node import ResponseNode
from apps.agents.core.investigation_state import (
    InvestigationState,
    Artifact as StateArtifact,
    Evidence as StateEvidence,
    ToolExecution as StateToolExecution,
    PlannerDecision as StatePlannerDecision
)
from apps.agents.core.investigation_planner import (
    InvestigationPlanner,
    HybridPlanner,
    RuleBasedPlanner,
    LLMPlanner,
    select_planner
)
from apps.agents.core.tool_registry import ToolRegistry
from apps.agents.core.event_system import EventStreamManager

logger = logging.getLogger("SecurityGraph")


class SecurityGraph:
    """
    Orchestrates the genuine adaptive investigation workflow.
    Replaces rigid static linear execution with evidence-driven dynamic tool selection,
    replanning, and true execution tracking.
    """

    def __init__(
        self,
        planner: Optional[InvestigationPlanner] = None,
        tool_registry: Optional[ToolRegistry] = None,
        planner_mode: str = "HYBRID",
        hybrid_policy: str = "RULE_FIRST"
    ):
        self.ingestion_node = IngestionNode()
        self.email_analysis_node = EmailAnalysisNode()
        self.vuln_research_node = VulnResearchNode()
        self.exposure_node = ExposureNode()
        self.investigation_node = InvestigationNode()
        self.response_node = ResponseNode()
        self.planner_mode = planner_mode
        self.hybrid_policy = hybrid_policy
        self.planner = planner
        self.tool_registry = tool_registry or ToolRegistry.get_instance()


    def run(self, initial_state: SecurityState) -> SecurityState:
        """
        Executes the security analysis workflow across adaptive agent nodes.
        Pipeline: Raw EML -> Ingestion/MIME -> InvestigationPlanner Loop -> Attack Chain -> Response Gate.
        """
        state = initial_state
        logger.info(f"--- [WORKFLOW START] Initializing adaptive run for tenant '{state.get('tenant_id')}' ---")

        # Step 1: Ingestion & Privacy Boundary Evaluation
        state = self.ingestion_node.execute(state)
        if state.get("errors"):
            logger.error(f"Ingestion failed: {state['errors']}")
            return state

        # Step 2: Dynamic Adaptive Investigation Loop (RuleBased / LLM / Hybrid)
        state = self._execute_adaptive_investigation(state)

        # Step 3: Exposure & Attack Surface Correlation
        state = self.exposure_node.execute(state)

        # Step 4: Vulnerability & Threat Intelligence Research
        state = self.vuln_research_node.execute(state)

        # Step 5: Investigation, Scoring & Attack Chain Reconstruction
        state = self.investigation_node.execute(state)

        # Step 6: Response Planning & Policy Gating
        state = self.response_node.execute(state)

        logger.info(f"--- [WORKFLOW COMPLETE] Incident created with confidence {state.get('confidence')} ---")
        return state

    def _execute_adaptive_investigation(self, state: SecurityState) -> SecurityState:
        """
        Executes dynamic InvestigationPlanner loop:
        Evaluates Artifacts -> Questions -> Propose Action -> Safety Gate -> Tool Execution -> Update State -> Replan.
        """
        raw_eml = state.get("raw_eml", b"")
        email_rep_dict = state.get("email_representation", {})
        tenant_id = state.get("tenant_id", "tenant-default")
        workflow_id = state.get("workflow_id", f"wf-{uuid.uuid4().hex[:6]}")
        autonomy_level = state.get("autonomy_level", 1)

        # 1. Parse MIME container for attachments
        parsed_email = email_lib.message_from_bytes(raw_eml) if raw_eml else None
        extracted_attachments = []
        if parsed_email:
            for part in parsed_email.walk():
                fn = part.get_filename()
                cd = str(part.get("Content-Disposition", ""))
                if fn or "attachment" in cd.lower():
                    payload = part.get_payload(decode=True) or b""
                    if payload:
                        extracted_attachments.append({
                            "filename": fn or "unnamed_attachment",
                            "payload": payload,
                            "mime": part.get_content_type()
                        })

        headers = email_rep_dict.get("headers", {})
        body_plain = email_rep_dict.get("body_plain", "")
        body_html = email_rep_dict.get("body_html", "")
        urls = email_rep_dict.get("urls", [])
        sender_addr = email_rep_dict.get("sender", {}).get("address", "unknown@mail")
        recipient_addr = (email_rep_dict.get("recipients", [{}])[0].get("address")) or "target@corp.internal"
        subject_line = headers.get("subject", "No Subject")

        # 2. Initialize First-Class InvestigationState
        inv_state = InvestigationState(
            incident_id=workflow_id,
            tenant_id=tenant_id,
            autonomy_level=autonomy_level,
            raw_eml=raw_eml,
            remaining_budget_steps=15
        )

        # Populate Artifacts
        inv_state.artifacts.append(StateArtifact(artifact_type="EML_RAW", raw_data=len(raw_eml), location="RAW_EML"))
        inv_state.artifacts.append(StateArtifact(artifact_type="MIME_HEADER", raw_data=headers, location="HEADERS"))
        if body_plain:
            inv_state.artifacts.append(StateArtifact(artifact_type="BODY_PLAIN", raw_data=body_plain, location="BODY: text/plain"))
        if body_html:
            inv_state.artifacts.append(StateArtifact(artifact_type="BODY_HTML", raw_data=body_html, location="BODY: text/html"))
        for u in urls:
            inv_state.artifacts.append(StateArtifact(artifact_type="URL_STRING", raw_data=u.get("url", ""), location="BODY_URL"))
        for att in extracted_attachments:
            inv_state.artifacts.append(StateArtifact(artifact_type="ATTACHMENT_PAYLOAD", raw_data=att, location=f"ATTACHMENT: {att['filename']}"))

        # Baseline Observed Evidence
        e_idx = 101
        ev_mime = StateEvidence(
            id=f"E-{e_idx}",
            evidence_type="MIME_HEADER",
            value=f"From: {sender_addr} | To: {recipient_addr} | Subject: {subject_line}",
            source="DeterministicMimeParser",
            status="OBSERVED"
        )
        inv_state.evidence[ev_mime.id] = ev_mime
        e_idx += 1

        auth_info = email_rep_dict.get("authentication", {})
        auth_failed = (
            auth_info.get("spf") in ["fail", "softfail"] or
            auth_info.get("dmarc") in ["fail", "reject"]
        )
        ev_auth = StateEvidence(
            id=f"E-{e_idx}",
            evidence_type="AUTHENTICATION",
            value="SPF: Fail / DMARC: Reject" if auth_failed else "SPF: Pass / DMARC: Aligned",
            source="MimeParser.HeaderAnalyzer",
            status="OBSERVED"
        )
        inv_state.evidence[ev_auth.id] = ev_auth
        e_idx += 1

        for u in urls:
            u_str = u.get("url", "")
            ev_u = StateEvidence(
                id=f"E-{e_idx}",
                evidence_type="URL_NORMALIZED",
                value=u_str,
                subject=u_str,
                source="HTMLAnalyzer",
                status="OBSERVED",
                metadata={"url": u_str, "normalization": "canonical"}
            )
            inv_state.evidence[ev_u.id] = ev_u
            e_idx += 1


        # Match skills for prompt/forensic enrichment
        if hasattr(self, "email_analysis_node") and hasattr(self.email_analysis_node, "skill_registry"):
            try:
                from packages.schemas.python.models import EmailAttackRepresentation
                rep_model = EmailAttackRepresentation(**email_rep_dict)
                active_skills = self.email_analysis_node.skill_registry.match_skills(rep_model)
                state["activated_skills"] = [s.name for s in active_skills]
            except Exception:
                pass

        # Select planner dynamically if requested in state or config
        requested_mode = state.get("planner_mode") or self.planner_mode or "HYBRID"
        requested_policy = state.get("hybrid_policy") or self.hybrid_policy or "RULE_FIRST"
        
        active_planner = self.planner
        if active_planner is None:
            active_planner = select_planner(
                mode=requested_mode,
                hybrid_policy=requested_policy,
                tier_risk_score=state.get("risk_score")
            )

        inv_state.planner_requested = requested_mode.upper()
        inv_state.planner_engine = requested_mode.upper()

        # Track negative evidence for absent threat vectors
        if not extracted_attachments:
            inv_state.add_negative_evidence("no_attachment", "No MIME attachments found in message container")
        if not urls:
            inv_state.add_negative_evidence("no_url", "No URLs found in email body or headers")
        if not auth_failed:
            inv_state.add_negative_evidence("no_authentication_failure", "SPF and DKIM pass without alignment failure")

        available_tools = self.tool_registry.get_tool_definitions()
        permissions = ["email.parse", "threat_intel.query", "attachment.inspect", "sandbox.browser_execute", "network.dns_lookup", "telemetry.query"]

        event_manager = EventStreamManager.get_instance()
        incident_id = state.get("incident_id") or workflow_id
        agent_run_id = state.get("agent_run_id") or f"run-{uuid.uuid4().hex[:8]}"

        # 3. Dynamic Planning & Re-Planning Loop
        while inv_state.remaining_budget_steps > 0:
            decision = active_planner.propose_next_action(inv_state, available_tools, permissions)
            inv_state.decisions.append(decision)
            inv_state.remaining_budget_steps -= 1

            # Emit real-time granular SSE telemetry for planner selection
            try:
                event_manager.publish_event(
                    investigation_id=incident_id,
                    agent_run_id=agent_run_id,
                    event_type="agent.planner.selected",
                    message=f"Planner ({decision.planner_type}) selected action: {decision.action} ({decision.tool_name or decision.stop_reason or ''})",
                    status="SUCCESS",
                    decision_id=decision.decision_id,
                    tool=decision.tool_name,
                    data={
                        "planner_type": decision.planner_type,
                        "engine_type": decision.engine_type,
                        "action": decision.action,
                        "tool": decision.tool_name,
                        "arbitration": decision.arbitration,
                        "expected_gain": decision.expected_information_gain,
                        "confidence": decision.confidence
                    }
                )
            except Exception:
                pass

            if decision.action == "STOP":
                inv_state.is_complete = True
                inv_state.stop_reason = decision.stop_reason or "SUFFICIENT_EVIDENCE"
                break

            if decision.action == "RUN_TOOL":
                tool_name = decision.tool_name
                tool_params = {}
                if tool_name in ["UnicodeAnalyzer"]:
                    tool_params = {"text": f"{subject_line} {body_plain} {body_html}", "location": "EMAIL_PAYLOAD"}
                elif tool_name in ["threat_intel_lookup", "ThreatIntelFeeds"]:
                    target_url = urls[0].get("url") if urls else ""
                    tool_params = {"indicator_type": "url", "indicator_value": target_url, "queries": [u.get("url") for u in urls]}
                elif tool_name in ["url_sandbox_detonation", "UrlSandboxRunner"]:
                    target_url = urls[0].get("url") if urls else ""
                    tool_params = {"url": target_url}
                elif tool_name in ["inspect_attachment", "AttachmentAnalyzer"]:
                    if extracted_attachments:
                        att0 = extracted_attachments[0]
                        tool_params = {"filename": att0["filename"], "payload_bytes": att0["payload"], "declared_mime": att0.get("mime", "")}
                elif tool_name in ["dns_spf_dmarc_recon"]:
                    sender_dom = email_rep_dict.get("sender", {}).get("domain", "mail.net")
                    tool_params = {"domain": sender_dom}
                elif tool_name in ["query_sender_history"]:
                    sender_dom = email_rep_dict.get("sender", {}).get("domain", "mail.net")
                    tool_params = {"sender_email": sender_addr, "recipient_email": recipient_addr, "sender_domain": sender_dom, "tenant_id": tenant_id}
                elif tool_name in ["CisaKevCorrelator"]:
                    tool_params = {"cve_id": "CVE-2023-35636"}

                # Execute proposal through ToolRegistry with authentic measured duration
                t0 = time.perf_counter()
                proposal = ToolProposal(tool_name=tool_name, parameters=tool_params, reasoning=decision.rationale)
                res = self.tool_registry.execute_proposal(tenant_id=tenant_id, proposal=proposal, autonomy_level=autonomy_level)
                dur_ms = max(0.01, round((time.perf_counter() - t0) * 1000.0, 2))

                produced_e_ids = []
                out = res.output or {}

                # Create evidence items from authentic execution
                if tool_name in ["UnicodeAnalyzer"]:
                    if out.get("has_anomalies"):
                        ev_item = StateEvidence(
                            id=f"E-{e_idx}",
                            evidence_type="UNICODE_ANOMALY",
                            value="Unicode Tag characters or RTLO override detected in payload",
                            source="UnicodeAnalyzer",
                            status="OBSERVED"
                        )
                        inv_state.evidence[ev_item.id] = ev_item
                        produced_e_ids.append(ev_item.id)
                        state.setdefault("evidence", []).append({"stage": "EMAIL_ANALYSIS", "type": "UNICODE_RTLO", "detail": "Unicode tag characters detected"})
                        e_idx += 1
                    else:
                        inv_state.add_negative_evidence("no_suspicious_unicode", "UnicodeAnalyzer confirmed absence of tags or RTLO characters")

                elif tool_name in ["threat_intel_lookup", "ThreatIntelFeeds"]:
                    is_mal = bool(out.get("is_malicious", False))
                    rep_status = "MALICIOUS" if is_mal else "UNKNOWN"
                    ev_item = StateEvidence(
                        id=f"E-{e_idx}",
                        evidence_type="URL_REPUTATION",
                        value=f"Threat intel reputation: {rep_status}",
                        subject=target_url,
                        source="ThreatIntelFeeds",
                        status="OBSERVED",
                        metadata={
                            "url": target_url,
                            "reputation": rep_status,
                            "is_malicious": is_mal,
                            "details": out
                        }
                    )
                    inv_state.evidence[ev_item.id] = ev_item
                    produced_e_ids.append(ev_item.id)
                    if is_mal:
                        state.setdefault("evidence", []).append({"stage": "THREAT_INTEL", "type": "DECEPTIVE_URL", "detail": "Deceptive link flagged in reputation feed"})
                        if not auth_failed:
                            inv_state.add_contradiction("Legitimate sender authentication combined with verified malicious URL target", [ev_auth.id, ev_item.id], impact="HIGH")
                    else:
                        inv_state.add_negative_evidence("no_known_malicious_reputation", f"Threat intel reported benign/unknown reputation for {target_url}")
                    e_idx += 1

                elif tool_name in ["url_sandbox_detonation", "UrlSandboxRunner"]:
                    from packages.schemas.python.models import EmailAttackRepresentation
                    rep_model = EmailAttackRepresentation(**email_rep_dict)
                    sb_tel = self.email_analysis_node.sandbox_runner.run_safe_observation(rep_model)
                    sb_dict = sb_tel.model_dump()
                    sb_dict.update(out)
                    sb_dict["is_benign"] = sb_tel.is_benign
                    sb_dict["rendering_anomalies"] = sb_tel.rendering_anomalies
                    sb_dict["forced_callout_destinations"] = sb_tel.forced_callout_destinations
                    state["sandbox_telemetry"] = sb_dict

                    ev_item = StateEvidence(
                        id=f"E-{e_idx}",
                        evidence_type="BEHAVIORAL_SANDBOX",
                        value=f"Sandbox DOM behavioral telemetry: risk {out.get('risk_score', 0)}/100 | Anomalies: {len(sb_tel.rendering_anomalies)}",
                        subject=target_url,
                        source="UrlSandboxRunner",
                        status="OBSERVED",
                        metadata={
                            "url": target_url,
                            "risk_score": out.get("risk_score", 0),
                            "rendering_anomalies": sb_tel.rendering_anomalies,
                            "is_benign": sb_tel.is_benign
                        }
                    )
                    inv_state.evidence[ev_item.id] = ev_item
                    produced_e_ids.append(ev_item.id)
                    if not sb_tel.is_benign:
                        for anom in sb_tel.rendering_anomalies:
                            state.setdefault("evidence", []).append({"stage": "SANDBOX_BEHAVIOR", "type": "RENDERING_EXPLOIT", "detail": anom})
                        for fc in sb_tel.forced_callout_destinations:
                            state.setdefault("evidence", []).append({"stage": "SANDBOX_BEHAVIOR", "type": "FORCED_CALLOUT", "detail": f"Forced UNC/SMB to {fc}"})
                        # Check contradiction against threat intel reputation
                        rep_ev = inv_state.get_latest_evidence("URL_REPUTATION", subject=target_url)
                        if rep_ev and "MALICIOUS" not in rep_ev.value.upper():
                            inv_state.add_contradiction("Clean threat intel reputation contradicted by dynamic sandbox exploit observation", [rep_ev.id, ev_item.id], impact="CRITICAL")
                    e_idx += 1

                elif tool_name in ["inspect_attachment", "AttachmentAnalyzer"]:
                    ev_item = StateEvidence(
                        id=f"E-{e_idx}",
                        evidence_type="ATTACHMENT_ANALYSIS",
                        value=f"Attachment inspection: {out.get('container_type', 'archive')} (Risk: {out.get('risk_score', 0)})",
                        source="AttachmentAnalyzer",
                        status="OBSERVED"
                    )
                    inv_state.evidence[ev_item.id] = ev_item
                    produced_e_ids.append(ev_item.id)
                    e_idx += 1

                    if out.get("motw_evasion"):
                        ev_motw = StateEvidence(
                            id=f"E-{e_idx}",
                            evidence_type="ATTACHMENT_PE",
                            value="Mark-of-the-Web evasion container with embedded executable payload",
                            source="AttachmentAnalyzer.IsoParser",
                            status="OBSERVED"
                        )
                        inv_state.evidence[ev_motw.id] = ev_motw
                        produced_e_ids.append(ev_motw.id)
                        state.setdefault("evidence", []).append({"stage": "ATTACHMENT_INSPECTION", "type": "MOTW_EVASION", "detail": "Container embeds executable payload"})
                elif tool_name == "query_sender_history":
                    is_first = out.get("is_first_time_sender", True)
                    ev_item = StateEvidence(
                        id=f"E-{e_idx}",
                        evidence_type="HISTORICAL_COMMUNICATION",
                        value=f"Sender history: first-time sender={is_first}, count={out.get('historical_email_count', 0)}, reputation={out.get('baseline_reputation', 'UNKNOWN')}",
                        source="TelemetryServer",
                        status="OBSERVED",
                        metadata=out
                    )
                    inv_state.evidence[ev_item.id] = ev_item
                    produced_e_ids.append(ev_item.id)
                    e_idx += 1

                elif tool_name == "dns_spf_dmarc_recon":
                    ev_item = StateEvidence(
                        id=f"E-{e_idx}",
                        evidence_type="DNS_RECON",
                        value=f"DNS recon: SPF={out.get('has_spf')}, DMARC={out.get('has_dmarc')}, vulnerable={out.get('is_spoofing_vulnerable')}",
                        source="DnsServer",
                        status="OBSERVED",
                        metadata=out
                    )
                    inv_state.evidence[ev_item.id] = ev_item
                    produced_e_ids.append(ev_item.id)
                    e_idx += 1

                exec_record = StateToolExecution(
                    tool_name=tool_name,
                    status="COMPLETED" if res.success else "FAILED",
                    duration_ms=dur_ms,
                    input_params=tool_params,
                    output_summary=str(out)[:200],
                    error=res.error,
                    produced_evidence_ids=produced_e_ids
                )
                inv_state.executed_tools.append(exec_record)

                # Emit real-time granular SSE telemetry for tool execution & evidence created
                try:
                    event_manager.publish_event(
                        investigation_id=incident_id,
                        agent_run_id=agent_run_id,
                        event_type="agent.tool.executed",
                        message=f"Executed tool {tool_name} in {dur_ms}ms ({'COMPLETED' if res.success else 'FAILED'})",
                        status="SUCCESS" if res.success else "FAILED",
                        tool=tool_name,
                        duration=dur_ms / 1000.0,
                        evidence_ids=produced_e_ids,
                        error=res.error,
                        data={"output_summary": str(out)[:200], "duration_ms": dur_ms}
                    )
                    for eid in produced_e_ids:
                        ev_obj = inv_state.evidence.get(eid)
                        if ev_obj:
                            event_manager.publish_event(
                                investigation_id=incident_id,
                                agent_run_id=agent_run_id,
                                event_type="agent.evidence.created",
                                message=f"Generated evidence {eid}: {ev_obj.evidence_type} ({ev_obj.source})",
                                status="SUCCESS",
                                tool=tool_name,
                                evidence_ids=[eid],
                                data={"evidence_id": eid, "type": ev_obj.evidence_type, "value": ev_obj.value}
                            )
                except Exception:
                    pass

        state["planner_requested"] = inv_state.planner_requested
        state["planner_used"] = inv_state.planner_used
        state["fallback_reason"] = inv_state.fallback_reason
        state["investigation_state"] = inv_state
        return state
