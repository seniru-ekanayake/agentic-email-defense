"""
InvestigationService: Manages incident lifecycles, correlated investigations,
and synthesizes evidence-grounded forensic artifacts for the SOC Dashboard.
Grounded strictly in observable execution events, real evidence, and transparent decision traces.
"""

import uuid
import datetime
import hashlib
import time
import logging
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from packages.schemas.python.models import SecurityState
from apps.agents.graph import SecurityGraph
from packages.attack_graph.src.sqlite_repository import SqliteAttackGraphRepository
from apps.agents.core.durable_storage import DurableStorage
from packages.attack_graph.src.models import AttackGraphData
from apps.agents.core.state_machine import AgentState, InvestigationStateMachine
from apps.agents.core.event_system import EventStreamManager, AgentLifecycleEvent
from apps.agents.core.forensic_ledger import (
    EvidenceItem,
    EvidenceStatus,
    ConfidenceLevel,
    HypothesisRecord,
    HypothesisStatus,
    HypothesisCategory,
    DecisionRecord,
    ToolExecutionRecord,
    ClaimEvidenceItem,
    ForensicAuditRecord,
    RiskDeltaItem,
    RiskScoreProvenance,
    VerdictExplanation,
    ResourceTelemetry,
    EvidenceGraph,
    EvidenceGraphNode,
    EvidenceGraphEdge,
    AgentDecisionState
)
from apps.agents.core.trust_score import TrustScoreCalculator, AgentTrustScore
from apps.agents.core.investigation_state import InvestigationState
from apps.agents.core.verdict_engine import EmailVerdict
from apps.agents.core.tool_registry import ToolRegistry
from apps.agents.core.agent_builder import get_planner_settings

logger = logging.getLogger("InvestigationService")


class ComprehensiveIncidentRecord(BaseModel):
    incident_id: str
    tenant_id: str
    title: str
    severity: str
    overall_risk_score: float
    confidence: float
    status: str = "OPEN"  # OPEN, TRIAGED, INVESTIGATING, CONTAINMENT_PROPOSED, CONTAINED, CLOSED
    sender: str = "unknown@mail"
    recipient: str = "unknown@corp"
    subject: str = "No Subject"
    target_identity: str
    mail_platform: str
    exposure_status: str
    interaction_required: str  # NONE, VIEW, CLICK, etc.
    cve: Optional[str] = None
    threat_category: str = "Standard Triage"
    timestamp: str = "Just now"

    # Deep Observability Artifacts
    attack_chain: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_summary: List[str] = Field(default_factory=list)
    recommended_actions: List[Dict[str, Any]] = Field(default_factory=list)
    pending_approvals: List[Dict[str, Any]] = Field(default_factory=list)
    resolved_approvals: List[Dict[str, Any]] = Field(default_factory=list)
    activated_skills: List[str] = Field(default_factory=list)
    graph_context: Optional[Dict[str, Any]] = None

    # Core Grounding Artifacts
    evidence_items: List[EvidenceItem] = Field(default_factory=list)
    hypotheses: List[HypothesisRecord] = Field(default_factory=list)
    decision_trace: List[DecisionRecord] = Field(default_factory=list)
    tool_executions: List[ToolExecutionRecord] = Field(default_factory=list)
    forensic_audit: ForensicAuditRecord = Field(default_factory=ForensicAuditRecord)
    claim_evidence_items: List[ClaimEvidenceItem] = Field(default_factory=list)
    evidence_graph: EvidenceGraph = Field(default_factory=EvidenceGraph)
    risk_provenance: RiskScoreProvenance = Field(default_factory=RiskScoreProvenance)
    explanation: VerdictExplanation = Field(default_factory=VerdictExplanation)
    telemetry: ResourceTelemetry = Field(default_factory=ResourceTelemetry)
    trust_score: AgentTrustScore = Field(default_factory=lambda: TrustScoreCalculator.calculate(0, [], [], [], 0))
    agent_decision_state: AgentDecisionState = Field(default_factory=lambda: AgentDecisionState(current_objective="Investigation completed"))
    state_history: List[Dict[str, Any]] = Field(default_factory=list)
    events: List[AgentLifecycleEvent] = Field(default_factory=list)

    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


# Alias for backwards compatibility
IncidentRecord = ComprehensiveIncidentRecord


def new_incident_id() -> str:
    return f"INC-{uuid.uuid4().hex[:6].upper()}"


def _confidence_level(value: float) -> ConfidenceLevel:
    if value >= 0.8:
        return ConfidenceLevel.HIGH
    if value >= 0.5:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


class InvestigationService:
    def __init__(self, graph_repo: Optional[Any] = None):
        self.storage = DurableStorage.get_instance()
        self.durable_storage = self.storage
        self.graph_repo = graph_repo or SqliteAttackGraphRepository(storage=self.storage)
        self.security_graph = SecurityGraph()
        self.security_graph.investigation_node.graph_repo = self.graph_repo
        self.event_stream = EventStreamManager.get_instance()
        self.tool_registry = ToolRegistry.get_instance()
        self._incidents_map: Dict[str, ComprehensiveIncidentRecord] = {}

    # ------------------------------------------------------------------ #
    def run_investigation(
        self,
        tenant_id: str,
        raw_eml: bytes,
        autonomy_level: int = 1,
        source_filename: str = "inbound_email.eml",
        incident_id: Optional[str] = None
    ) -> ComprehensiveIncidentRecord:
        """Runs the investigation pipeline and assembles a report strictly from recorded evidence."""
        t0 = time.time()
        incident_id = incident_id or new_incident_id()
        agent_run_id = f"run-{uuid.uuid4().hex[:8]}"
        state_machine = InvestigationStateMachine(incident_id)
        state_machine.transition_to(AgentState.INITIALIZING, reason="Allocated investigation worker")
        self.event_stream.publish_event(investigation_id=incident_id, agent_run_id=agent_run_id, event_type="agent.started",
                                        message=f"Investigation {incident_id} initiated for tenant '{tenant_id}'.")

        eml_sha256 = hashlib.sha256(raw_eml).hexdigest()
        settings = get_planner_settings(tenant_id)
        planner_mode, hybrid_policy = settings.planner_mode, settings.hybrid_arbitration_policy

        initial_state: SecurityState = {
            "tenant_id": tenant_id,
            "incident_id": incident_id,
            "agent_run_id": agent_run_id,
            "workflow_id": incident_id,
            "autonomy_level": autonomy_level,
            "raw_eml": raw_eml,
            "planner_mode": planner_mode,
            "hybrid_policy": hybrid_policy,
        }

        state_machine.transition_to(AgentState.PARSING, reason="MIME & header extraction")
        state_machine.transition_to(AgentState.INVESTIGATING, reason="Planner-driven tool loop")
        final_state = self.security_graph.run(initial_state)
        if final_state.get("errors") or "verdict" not in final_state:
            self.event_stream.publish_event(investigation_id=incident_id, agent_run_id=agent_run_id, event_type="agent.failed",
                                            message=f"Investigation failed: {final_state.get('errors')}", status="FAILED")
            raise ValueError(f"Email could not be investigated: {final_state.get('errors') or 'pipeline error'}")
        state_machine.transition_to(AgentState.GENERATING_VERDICT, reason="Computing evidence-based verdict")

        inv: InvestigationState = final_state["investigation_state"]
        verdict: EmailVerdict = final_state["verdict"]
        report = final_state.get("incident_report", {})
        rep = final_state.get("email_representation", {}) or {}
        pending_approvals = final_state.get("pending_approvals", [])
        response_executions = final_state.get("executed_tools", [])

        headers = rep.get("headers", {}) or {}
        sender_addr = (rep.get("sender") or {}).get("address") or "unknown"
        recipient_addr = ((rep.get("recipients") or [{}])[0].get("address")) or "unknown"
        subject_line = headers.get("Subject") or headers.get("subject") or "(no subject)"

        # --- Evidence: 1:1 with the typed evidence recorded during the investigation ---
        evidence_items = [
            EvidenceItem(
                evidence_id=e.id, type=e.evidence_type, value=e.value, source=e.source, timestamp=e.timestamp,
                confidence=_confidence_level(e.confidence),
                status=EvidenceStatus(e.status) if e.status in EvidenceStatus.__members__ else EvidenceStatus.OBSERVED,
                metadata={**{k: v for k, v in e.metadata.items() if k != "details"}, **({"subject": e.subject} if e.subject else {})},
            )
            for e in inv.evidence.values()
        ]
        evidence_ids = {e.evidence_id for e in evidence_items}

        # --- Hypotheses: the planner's own hypotheses and their evidence ---
        status_map = {"SUPPORTED": HypothesisStatus.SUPPORTED, "CONTRADICTED": HypothesisStatus.REJECTED,
                      "CLOSED": HypothesisStatus.REJECTED}
        hypotheses = [
            HypothesisRecord(
                hypothesis_id=h.id, statement=h.statement,
                status=status_map.get(h.status, HypothesisStatus.UNRESOLVED),
                category=HypothesisCategory.HYPOTHESIS,
                evidence_ids=[i for i in h.supporting_evidence_ids + h.contradicting_evidence_ids if i in evidence_ids],
            )
            for h in inv.hypotheses.values()
        ]

        # --- Decision trace: one record per planner decision ---
        decision_trace: List[DecisionRecord] = []
        # Evidence that motivates work on each question (what the planner was looking at).
        question_triggers = {
            "Q-01": ("AUTHENTICATION",), "Q-02": ("MIME_HEADER",), "Q-03": ("URL_NORMALIZED",),
            "Q-04": ("MONIKER_URI", "UNC_PATH"), "Q-05": ("MIME_HEADER",), "Q-06": ("CVE_CANDIDATE",),
        }
        resolved_ev = [q.resolution_evidence_id for q in inv.questions.values() if q.status == "RESOLVED" and q.resolution_evidence_id]
        for d in inv.decisions:
            if d.action == "RUN_TOOL":
                trig = [e.id for q in d.addresses_questions for e in inv.evidence.values()
                        if e.evidence_type in question_triggers.get(q, ())]
            else:
                trig = resolved_ev or [e.id for e in inv.evidence.values() if e.evidence_type in ("MIME_HEADER", "AUTHENTICATION")]
            trig = list(dict.fromkeys(i for i in trig + [i for i in d.evidence_ids_used if i in evidence_ids] if i))
            hyp = ", ".join(d.hypothesis_ids) or (f"Stop condition: {d.stop_reason}" if d.action != "RUN_TOOL" else None)
            executed = next((t for t in inv.executed_tools if t.tool_name == d.tool_name), None) if d.action == "RUN_TOOL" else None
            decision_trace.append(DecisionRecord(
                decision_id=d.decision_id,
                observed=d.rationale,
                evidence_ids=trig,
                decision=f"{d.action} {d.tool_name}" if d.tool_name else f"{d.action} ({d.stop_reason})",
                action=d.tool_name or f"{d.action} ({d.stop_reason})",
                reason=d.rationale,
                result=(f"{executed.status}: produced {executed.produced_evidence_ids or 'no evidence'}" if executed
                        else (f"Investigation ended: {d.stop_reason}" if d.action != "RUN_TOOL" else "Tool not executed")),
                impact=f"Expected information gain {d.expected_information_gain:.2f}",
                confidence=_confidence_level(d.confidence),
                timestamp=d.timestamp,
                trigger_evidence_ids=trig,
                hypothesis_tested=hyp,
                alternatives_considered=[f"{a.get('tool')}: {a.get('reason', '')}" for a in d.alternatives_considered] or ["none eligible"],
                tool_selected_rationale=d.rationale,
                inputs_rationale=f"Planner: {d.planner_type} ({d.engine_type})" + (f" | arbitration: {d.arbitration.get('mode')}" if d.arbitration else ""),
                result_observed=((", ".join(executed.produced_evidence_ids) or f"{executed.status}: no new evidence") if executed
                                 else f"Stopped: {d.stop_reason or d.action}"),
                belief_state_impact=f"Confidence {d.confidence_before:.2f} -> {d.confidence_after:.2f}",
                next_planned_action="Re-plan with updated evidence" if d.action == "RUN_TOOL" else "Compute verdict",
                planner_type=d.planner_type,
                model=d.model,
                reasoning_steps=d.reasoning_steps,
                reasoning_trace=d.reasoning_trace,
                llm_proposal=d.llm_proposal,
                override_reason=d.override_reason,
            ))

        # --- Tool executions: only tools that actually ran ---
        tool_executions = [
            ToolExecutionRecord(
                execution_id=t.id, tool_name=t.tool_name, status=t.status, input_parameters=t.input_params,
                started_at=t.timestamp, duration_ms=t.duration_ms, result_summary=t.output_summary,
                evidence_created=t.produced_evidence_ids, source=f"ToolRegistry.{t.tool_name}",
                confidence=ConfidenceLevel.HIGH if t.status == "COMPLETED" else ConfidenceLevel.LOW, error=t.error,
            )
            for t in inv.executed_tools
        ]
        failed_tools = sum(1 for t in tool_executions if t.status != "COMPLETED")

        # --- Forensic audit: derived from recorded executions only ---
        network_requests: List[Dict[str, Any]] = []
        sandbox_executions: List[Dict[str, Any]] = []
        for t in inv.executed_tools:
            ev = [inv.evidence[i] for i in t.produced_evidence_ids if i in inv.evidence]
            if t.tool_name in ("ThreatIntelFeeds", "threat_intel_lookup"):
                feeds = (ev[0].metadata.get("details", {}) or {}).get("feeds", {}) if ev else {}
                network_requests.append({"tool": t.tool_name, "target": t.input_params.get("indicator_value"),
                                         "feeds": feeds, "status": t.status, "duration_ms": t.duration_ms})
            elif t.tool_name in ("UrlSandboxRunner", "url_sandbox_detonation"):
                meta = ev[0].metadata if ev else {}
                network_requests.append({"tool": t.tool_name, "target": t.input_params.get("url"), "method": "GET",
                                         "status": t.status, "duration_ms": t.duration_ms})
                sandbox_executions.append({"engine": "Static HTTP fetch (no browser execution)", "target": t.input_params.get("url"),
                                           "verdict": meta.get("verdict"), "final_destination_url": meta.get("final_destination_url"),
                                           "duration_ms": t.duration_ms})
            elif t.tool_name == "dns_spf_dmarc_recon":
                network_requests.append({"tool": t.tool_name, "target": t.input_params.get("domain"), "method": "DoH",
                                         "status": t.status, "duration_ms": t.duration_ms})

        forensic_audit = ForensicAuditRecord(
            files_read=[{"file_path": source_filename, "size_bytes": len(raw_eml), "sha256": eml_sha256,
                         "read_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}],
            tools_executed=[t.model_dump() for t in tool_executions],
            network_requests=network_requests,
            database_queries=[],
            llm_calls=list(inv.llm_calls),
            sandbox_executions=sandbox_executions,
            evidence_created=[e.evidence_id for e in evidence_items],
            actions_executed=response_executions,
        )

        # --- Claims: every SUPPORTED claim cites the evidence that produced it ---
        auth = next((e for e in inv.evidence.values() if e.evidence_type == "AUTHENTICATION"), None)
        auth_result = auth.metadata.get("result") if auth else "UNKNOWN"
        claims: List[ClaimEvidenceItem] = [
            ClaimEvidenceItem(claim=f"Message from {sender_addr} was addressed to {recipient_addr}.",
                              evidence_ids=[i for i in ["E-101"] if i in evidence_ids], source="MimeParser",
                              execution="RFC 5322 parsing", confidence=ConfidenceLevel.HIGH, status="SUPPORTED"),
            ClaimEvidenceItem(
                claim={"FAIL": "Sender authentication failed.", "PASS": "Sender authentication passed.",
                       "UNKNOWN": "Sender authentication could not be verified (no Authentication-Results)."}[auth_result],
                evidence_ids=[auth.id] if auth else [], source="MimeParser.AuthenticationResults",
                execution="Authentication-Results header parsing",
                confidence=ConfidenceLevel.HIGH if auth_result != "UNKNOWN" else ConfidenceLevel.UNKNOWN,
                status="SUPPORTED" if auth_result != "UNKNOWN" else "UNKNOWN"),
        ]
        for f in verdict.factors:
            src = inv.evidence[f.evidence_id].source if f.evidence_id in inv.evidence else "unknown"
            claims.append(ClaimEvidenceItem(claim=f"{f.component}: {f.reason}.", evidence_ids=[f.evidence_id], source=src,
                                            execution="Verdict engine factor", confidence=ConfidenceLevel.HIGH, status="SUPPORTED"))
        if verdict.cve:
            claims.append(ClaimEvidenceItem(
                claim=f"{verdict.cve} is {'listed' if verdict.cve_in_kev else 'not confirmed'} in the CISA KEV catalog.",
                evidence_ids=[e.id for e in inv.evidence.values() if e.evidence_type in ("CISA_KEV_MATCH", "CVE_CANDIDATE")],
                source="CisaKevCorrelator", execution="Local CISA KEV subset lookup",
                confidence=ConfidenceLevel.HIGH if verdict.cve_in_kev else ConfidenceLevel.MEDIUM,
                status="SUPPORTED" if verdict.cve_in_kev else "UNKNOWN"))
        claims.append(ClaimEvidenceItem(claim="Whether the recipient opened or rendered the message is unknown.", evidence_ids=[],
                                        source="N/A", execution="No endpoint or mailbox telemetry available",
                                        confidence=ConfidenceLevel.LOW, status="UNKNOWN"))
        unsupported_claims = sum(1 for c in claims if c.status == "SUPPORTED" and not c.evidence_ids)

        # --- Evidence graph ---
        root_id = "node-email"
        nodes = [EvidenceGraphNode(id=root_id, label=f"Email ({subject_line[:24]})", type="EMAIL", value=subject_line,
                                   source="MimeParser", timestamp=evidence_items[0].timestamp if evidence_items else "",
                                   confidence="HIGH", status="OBSERVED", properties={"message_id": rep.get("message_id")})]
        edges: List[EvidenceGraphEdge] = []
        for e in evidence_items:
            if e.type == "MIME_HEADER":
                continue
            nodes.append(EvidenceGraphNode(id=f"node-{e.evidence_id}", label=f"{e.type}: {e.value[:32]}", type=e.type, value=e.value,
                                           source=e.source, timestamp=e.timestamp, confidence=e.confidence.value,
                                           status=e.status.value, properties=e.metadata))
            edges.append(EvidenceGraphEdge(source=root_id, target=f"node-{e.evidence_id}", relation=f"HAS_{e.type}"))
        evidence_graph = EvidenceGraph(nodes=nodes, edges=edges)

        # --- Risk provenance: exactly the verdict factors ---
        running, deltas = 0.0, []
        for f in verdict.factors:
            running = min(100.0, running + f.delta)
            deltas.append(RiskDeltaItem(component=f.component, delta=f.delta, reason=f.reason, evidence_id=f.evidence_id,
                                        resulting_score=round(running, 1)))
        risk_provenance = RiskScoreProvenance(baseline_score=0.0, final_score=verdict.risk_score, adjustments=deltas)

        # --- Explanation ---
        tools_run = [t.tool_name for t in inv.executed_tools]
        explanation = VerdictExplanation(
            what_did_we_observe=[f"Message from '{sender_addr}' to '{recipient_addr}' (subject: {subject_line[:80]})."]
                                + [f"{e.type}: {e.value[:140]}" for e in evidence_items if e.type not in ("MIME_HEADER",)],
            what_does_it_mean=(f"Verdict {verdict.verdict} ({verdict.severity}, risk {verdict.risk_score}/100): {verdict.title}."
                               if verdict.factors else "No malicious indicators were observed in the evidence collected."),
            what_evidence_supports_it=[f.evidence_id for f in verdict.factors],
            what_did_we_investigate=["MIME structure, headers and Authentication-Results", "Links, URI schemes and Unicode content"]
                                    + [f"Tool: {t}" for t in tools_run],
            what_did_we_not_investigate=["Endpoint/EDR telemetry", "Mailbox access or rendering logs", "Dynamic (browser) execution of links or attachments"],
            what_remains_unknown=[f"{k}: {v.get('detail', '')}" for k, v in inv.negative_evidence.items()
                                  if k in ("authentication_results_absent", "reputation_unavailable")]
                                 + ["Whether the recipient interacted with the message"],
            why_did_the_risk_score_change=[f"+{f.delta} {f.component} ({f.evidence_id})" for f in verdict.factors] or ["No risk factors observed."],
            what_should_the_analyst_do_next=(
                ["Review and authorize the pending containment proposals."] if pending_approvals else
                (["Review the message; consider blocking the sender if more messages appear."] if verdict.verdict == "SUSPICIOUS"
                 else ["No action required."])),
        )

        elapsed = round(time.time() - t0, 3)
        llm_model = next((c.get("model") for c in inv.llm_calls if c.get("model")), None)
        telemetry = ResourceTelemetry(
            execution_time_seconds=elapsed,
            tool_calls_count=len(tool_executions),
            tokens_input=sum(int(c.get("tokens_prompt", 0)) for c in inv.llm_calls),
            tokens_output=sum(int(c.get("tokens_completion", 0)) for c in inv.llm_calls),
            llm_model=llm_model,
            llm_provider="openrouter" if inv.llm_calls else None,
            api_latency_ms=round(sum(t.duration_ms for t in inv.executed_tools) + sum(float(c.get("latency_ms", 0)) for c in inv.llm_calls), 2),
            network_calls_count=len(network_requests) + len(inv.llm_calls),
            evidence_items_count=len(evidence_items),
            hypotheses_count=len(hypotheses),
            decisions_count=len(decision_trace),
            errors_count=failed_tools + sum(1 for c in inv.llm_calls if c.get("status") not in ("COMPLETED",)),
            retries_count=0,
            estimated_cost_usd=0.0,
        )

        trust_score = TrustScoreCalculator.calculate(
            evidence_items_count=len(evidence_items),
            claims=[c.model_dump() for c in claims],
            tools_executed=[t.model_dump() for t in tool_executions],
            decisions=[d.model_dump() for d in decision_trace],
            provenance_adjustments_count=len(deltas),
            unsupported_claims_count=unsupported_claims,
            failed_tools_count=failed_tools,
        )

        for p in pending_approvals:
            if p.get("approval_token"):
                self.event_stream.publish_event(
                    investigation_id=incident_id, agent_run_id=agent_run_id, event_type="agent.proposal.created",
                    message=p.get("reasoning", ""), status="PENDING_APPROVAL", tool=p["tool_name"],
                    data={"approval_token": p["approval_token"], "tool_name": p["tool_name"], "risk_level": p.get("risk_level"),
                          "parameters": p.get("parameters", {}), "target_identity": recipient_addr},
                )
        if pending_approvals:
            state_machine.transition_to(AgentState.WAITING_FOR_APPROVAL, reason="Containment proposals require analyst authorization")
        else:
            state_machine.transition_to(AgentState.COMPLETED, reason="Investigation completed")
        self.event_stream.publish_event(
            investigation_id=incident_id, agent_run_id=agent_run_id, event_type="agent.completed",
            message=f"Investigation completed: {verdict.verdict} / {verdict.severity} (risk {verdict.risk_score}/100)",
            status="SUCCESS", duration=elapsed,
        )

        record = ComprehensiveIncidentRecord(
            incident_id=incident_id,
            tenant_id=tenant_id,
            title=verdict.title,
            severity=verdict.severity,
            overall_risk_score=verdict.risk_score,
            confidence=verdict.confidence,
            status="CONTAINMENT_PROPOSED" if pending_approvals else ("TRIAGED" if verdict.verdict != "BENIGN" else "CLOSED"),
            sender=sender_addr,
            recipient=recipient_addr,
            subject=subject_line,
            target_identity=recipient_addr,
            mail_platform=report.get("mail_platform", "Unknown"),
            exposure_status=report.get("exposure_status", "Unknown"),
            interaction_required=verdict.interaction_required,
            cve=verdict.cve,
            threat_category=verdict.threat_category,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            attack_chain=report.get("attack_chain", []),
            mitre_techniques=report.get("mitre_techniques", []),
            evidence_summary=report.get("evidence_summary", []),
            recommended_actions=report.get("recommended_actions", []),
            pending_approvals=pending_approvals,
            activated_skills=list(inv.activated_skills),
            evidence_items=evidence_items,
            hypotheses=hypotheses,
            decision_trace=decision_trace,
            tool_executions=tool_executions,
            forensic_audit=forensic_audit,
            claim_evidence_items=claims,
            evidence_graph=evidence_graph,
            risk_provenance=risk_provenance,
            explanation=explanation,
            telemetry=telemetry,
            trust_score=trust_score,
            agent_decision_state=AgentDecisionState(
                current_objective=f"Triaged: {subject_line[:40]}",
                evidence_considered_count=len(evidence_items),
                tools_available_count=len(self.tool_registry.get_tool_definitions()),
                tools_executed_count=len(tool_executions),
                tools_remaining_count=0,
                current_hypothesis=verdict.title,
                next_action="Awaiting analyst containment authorization" if pending_approvals else "None",
                reason=f"Planner stop reason: {inv.stop_reason}",
                risk_level=verdict.severity,
            ),
            state_history=state_machine.get_history(),
            events=self.event_stream.get_events(incident_id),
            graph_context=final_state.get("graph_context"),
        )
        self._incidents_map[incident_id] = record

        try:
            self.storage.save_incident(record.model_dump())
            self.storage.save_evidence_batch(incident_id, [e.model_dump() for e in evidence_items])
            self.storage.save_decisions_batch(incident_id, [d.model_dump() for d in decision_trace])
            self.storage.save_tool_executions_batch(incident_id, [t.model_dump() for t in tool_executions])
            self.storage.save_investigation_state(incident_id, tenant_id, inv.model_dump(exclude={"raw_eml"}))
            for ev in self.event_stream.get_events(incident_id):
                self.storage.save_event(ev.model_dump())
        except Exception as e:
            logger.error(f"Failed to persist incident {incident_id}: {e}")
            raise
        self.event_stream.forget(incident_id)

        logger.info(f"Incident {incident_id}: {verdict.verdict}/{verdict.severity} risk={verdict.risk_score}")
        return record

    def update_status(self, incident_id: str, tenant_id: str, status: str) -> ComprehensiveIncidentRecord:
        rec = self.get_incident(incident_id, tenant_id=tenant_id)
        if rec is None:
            raise KeyError(incident_id)
        rec.status = status
        rec.updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.storage.save_incident(rec.model_dump())
        self._incidents_map[incident_id] = rec
        return rec

    def resolve_approval(self, tenant_id: str, token: str, outcome: str, actor: str) -> None:
        """Moves an acted-on proposal from pending to resolved and updates the incident status."""
        stored = self.storage.get_approval_token(token) or {}
        incident_id = stored.get("incident_id")
        if not incident_id or stored.get("tenant_id") != tenant_id:
            return
        rec = self.get_incident(incident_id, tenant_id=tenant_id)
        if rec is None:
            return
        remaining = [p for p in rec.pending_approvals if p.get("approval_token") != token]
        resolved = [dict(p, outcome=outcome, actor=actor,
                         resolved_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
                    for p in rec.pending_approvals if p.get("approval_token") == token]
        if not resolved:
            return
        rec.pending_approvals = remaining
        rec.resolved_approvals = rec.resolved_approvals + resolved
        if not remaining and rec.status == "CONTAINMENT_PROPOSED":
            rec.status = "CONTAINED" if any(r["outcome"] == "DISPATCHED" for r in rec.resolved_approvals) else "TRIAGED"
        rec.updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.storage.save_incident(rec.model_dump())
        self._incidents_map[incident_id] = rec

    def list_incidents(self, tenant_id: Optional[str] = None, limit: Optional[int] = 100) -> List[ComprehensiveIncidentRecord]:
        """Returns incidents ledger, prioritizing durable storage with in-memory caching."""
        try:
            durable_records = self.storage.list_incidents(tenant_id, limit=limit)
            if durable_records:
                loaded = []
                for d in durable_records:
                    try:
                        rec = ComprehensiveIncidentRecord(**d)
                        self._incidents_map[rec.incident_id] = rec
                        loaded.append(rec)
                    except Exception:
                        pass
                if loaded:
                    return loaded
        except Exception as e:
            logger.warning(f"Failed to read from durable storage: {e}")

        incs = list(self._incidents_map.values())
        if tenant_id:
            incs = [i for i in incs if i.tenant_id == tenant_id]
        if limit and limit > 0:
            incs = incs[:limit]
        return incs

    def get_incident(self, incident_id: str, tenant_id: Optional[str] = None) -> Optional[ComprehensiveIncidentRecord]:
        rec = self._incidents_map.get(incident_id)
        if not rec:
            try:
                d = self.storage.get_incident(incident_id)
                if d:
                    rec = ComprehensiveIncidentRecord(**d)
                    self._incidents_map[incident_id] = rec
            except Exception as e:
                logger.warning(f"Failed to load incident {incident_id} from durable storage: {e}")

        if rec is not None and tenant_id is not None:
            if rec.tenant_id != tenant_id:
                raise PermissionError(
                    f"Access Denied: Incident '{incident_id}' belongs to tenant '{rec.tenant_id}', not '{tenant_id}'."
                )
        return rec

    def get_attack_graph(self, incident_id: str) -> AttackGraphData:
        inc = self.get_incident(incident_id)
        if inc and inc.graph_context:
            return AttackGraphData(**inc.graph_context)
        return self.graph_repo.to_graph_json()
