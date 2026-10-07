"""
InvestigationState: First-Class Evidence & Hypothesis Data Models for Adaptive Planning.
Maintains persistent Artifacts, Observations, Evidence, Hypotheses, Unresolved Questions,
ToolExecutions, PlannerDecisions, Contradictions, and Final Verdicts.
"""

from __future__ import annotations

import uuid
import time
import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class Artifact(BaseModel):
    id: str = Field(default_factory=lambda: f"art-{uuid.uuid4().hex[:8]}")
    artifact_type: str  # EML_RAW, MIME_HEADER, BODY_HTML, BODY_PLAIN, ATTACHMENT_PAYLOAD, URL_STRING
    raw_data: Any
    location: str  # e.g., "HEADER: Subject", "BODY: text/html", "ATTACHMENT: invoice.zip"
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class Evidence(BaseModel):
    id: str  # E-101, E-102
    evidence_type: str  # MIME_HEADER, AUTHENTICATION, UNICODE_ANOMALY, MONIKER_URI, LOCAL_FILE_URI, UNC_PATH, URL_REPUTATION, ATTACHMENT_PE, ATTACHMENT_MACRO, CISA_KEV_MATCH
    value: str
    source: str
    confidence: float = 0.95
    status: str = "OBSERVED"  # OBSERVED, INFERRED, UNKNOWN, CONTRADICTED
    location: Optional[str] = None
    subject: Optional[str] = None  # Exact entity under investigation, e.g. canonical URL, sender address, attachment filename
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())



class Hypothesis(BaseModel):
    id: str  # H-001, H-002, etc.
    statement: str
    category: str  # CREDENTIAL_PHISHING, MALICIOUS_REDIRECT, ATTACHMENT_EXECUTION, IMPERSONATION, EXPLOIT_ATTEMPT, BENIGN_COMMUNICATION
    status: str = "HYPOTHESIS"  # HYPOTHESIS, SUPPORTED, WEAKENED, CONTRADICTED, CLOSED
    confidence: float = 0.5
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    contradicting_evidence_ids: List[str] = Field(default_factory=list)
    unresolved_question_ids: List[str] = Field(default_factory=list)


class Question(BaseModel):
    id: str  # Q-001, Q-002
    text: str
    priority: float = 1.0  # Higher priority questions are addressed first
    category: str
    related_hypothesis_id: Optional[str] = None
    status: str = "UNRESOLVED"  # UNRESOLVED, RESOLVED, ABANDONED
    resolution_evidence_id: Optional[str] = None


class ToolExecution(BaseModel):
    id: str = Field(default_factory=lambda: f"exec-{uuid.uuid4().hex[:8]}")
    tool_name: str
    status: str = "COMPLETED"  # COMPLETED, FAILED, TIMEOUT, SKIPPED
    duration_ms: float = 0.0
    input_params: Dict[str, Any] = Field(default_factory=dict)
    output_summary: str = ""
    error: Optional[str] = None
    produced_evidence_ids: List[str] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class LLMDecisionProposal(BaseModel):
    """Strict structured proposal schema for LLM-driven planning decisions."""
    decision: str = Field(description="Must be RUN_TOOL, STOP, or ESCALATE")
    tool: Optional[str] = Field(default=None, description="Must match registered tool name exactly")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Typed parameters for tool execution")
    question_id: Optional[str] = Field(default=None, description="The security question addressed (e.g. Q-01, Q-02, Q-03)")
    evidence_ids: List[str] = Field(default_factory=list, description="IDs of observed evidence motivating this decision")
    expected_information_gain: float = Field(default=0.5, ge=0.0, le=1.0, description="Estimated information gain (0.0 to 1.0)")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence in this decision (0.0 to 1.0)")
    rationale_summary: str = Field(default="", description="Concise operational rationale (required for RUN_TOOL)")
    alternatives: List[Dict[str, str]] = Field(default_factory=list, description="Alternative tools considered and rejection reason")

    model_config = {"extra": "forbid"}


class PlannerDecision(BaseModel):
    decision_id: str = Field(default_factory=lambda: f"D-{uuid.uuid4().hex[:6].upper()}")
    action: str  # RUN_TOOL, ASK_HUMAN, STOP, ESCALATE
    engine_type: str = "RULE_ENGINE"  # RULE_ENGINE, LLM_PLANNER, HYBRID
    planner_type: str = "RULE"  # RULE, LLM, HYBRID
    tool_name: Optional[str] = None
    selected_action: str = "STOP"
    selected_tool: Optional[str] = None
    tool_arguments: Dict[str, Any] = Field(default_factory=dict)
    rationale: str
    rationale_summary: str = ""
    question_id: Optional[str] = None
    hypothesis_ids: List[str] = Field(default_factory=list)
    addresses_questions: List[str] = Field(default_factory=list)
    expected_information_gain: float = 0.0
    estimated_cost: float = 0.0
    confidence_before: float = 0.5
    confidence_after: float = 0.5
    confidence: float = 0.5
    stop_reason: Optional[str] = None  # SUFFICIENT_EVIDENCE, NO_USEFUL_TOOLS, BUDGET_EXHAUSTED, DEPENDENCY_UNAVAILABLE, HUMAN_APPROVAL_REQUIRED, CONTRADICTORY_EVIDENCE, INSUFFICIENT_CONFIDENCE, RATE_LIMIT_REACHED, REPLANNING_LIMIT_REACHED
    alternatives_considered: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_ids_used: List[str] = Field(default_factory=list)
    policy_constraints: List[str] = Field(default_factory=list)
    arbitration: Optional[Dict[str, Any]] = None  # Documents Rule vs LLM proposals and consensus reasoning in Hybrid mode
    reasoning_steps: List[str] = Field(default_factory=list)  # human-readable chain explaining this decision
    reasoning_trace: Optional[str] = None  # the model's own thought text, when the provider returns it
    llm_proposal: Optional[Dict[str, Any]] = None  # what the LLM proposed (also when it was overridden)
    override_reason: Optional[str] = None  # why the pipeline did not follow the LLM proposal
    model: Optional[str] = None
    provider: Optional[str] = None
    latency_ms: float = 0.0
    tokens_used: int = 0
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class Contradiction(BaseModel):
    id: str = Field(default_factory=lambda: f"contra-{uuid.uuid4().hex[:6]}")
    description: str
    conflicting_evidence_ids: List[str] = Field(default_factory=list)
    resolution: str = "UNRESOLVED"
    impact: str = "MEDIUM"


class Verdict(BaseModel):
    final_verdict: str = "BENIGN"  # BENIGN, SUSPICIOUS, MALICIOUS, CRITICAL
    overall_risk_score: float = 0.0
    confidence: float = 0.5
    title: str = "Investigation Completed"
    summary: str = ""
    target_cve: Optional[str] = None  # UNKNOWN unless verified via CISA KEV/NVD correlation
    primary_threat_category: str = "Standard Triage"


class InvestigationState(BaseModel):
    incident_id: str
    tenant_id: str
    autonomy_level: int = 1
    raw_eml: bytes = b""
    
    # Dynamic Planning State
    artifacts: List[Artifact] = Field(default_factory=list)
    evidence: Dict[str, Evidence] = Field(default_factory=dict)
    negative_evidence: Dict[str, Any] = Field(default_factory=dict)
    hypotheses: Dict[str, Hypothesis] = Field(default_factory=dict)
    questions: Dict[str, Question] = Field(default_factory=dict)
    executed_tools: List[ToolExecution] = Field(default_factory=list)
    decisions: List[PlannerDecision] = Field(default_factory=list)
    contradictions: List[Contradiction] = Field(default_factory=list)
    
    # Budget & Limits
    remaining_budget_steps: int = 15
    start_time: float = Field(default_factory=time.time)
    max_duration_seconds: float = 30.0
    llm_call_count: int = 0
    llm_tokens_total: int = 0
    replanning_cycle_count: int = 0
    llm_calls: List[Dict[str, Any]] = Field(default_factory=list)
    activated_skills: List[str] = Field(default_factory=list)  # forensic playbooks matched to this email
    playbook_context: str = ""  # trusted playbook guidance given to the LLM planner  # every real LLM request: model, status, latency, tokens, error
    
    # Engine Observability
    planner_engine: str = "RULE_ENGINE"
    planner_requested: str = "RULE"
    planner_used: str = "RULE"
    fallback_reason: Optional[str] = None
    is_complete: bool = False
    stop_reason: Optional[str] = None
    verdict: Optional[Verdict] = None

    def add_negative_evidence(self, indicator: str, detail: str = ""):
        """Explicitly records the verified absence of a threat indicator."""
        self.negative_evidence[indicator] = {
            "absent": True,
            "detail": detail,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

    def add_contradiction(self, description: str, conflicting_evidence_ids: List[str], impact: str = "MEDIUM") -> Contradiction:
        """Records a conflict between observed evidence items."""
        contra = Contradiction(
            description=description,
            conflicting_evidence_ids=conflicting_evidence_ids,
            impact=impact
        )
        self.contradictions.append(contra)
        return contra

    def get_latest_evidence(self, evidence_type: str, subject: Optional[str] = None) -> Optional[Evidence]:
        """
        Retrieves the latest observed evidence strictly matching the requested evidence_type and optional subject.
        Iterates in reverse insertion order so the most recent findings take precedence.
        """
        for ev in reversed(list(self.evidence.values())):
            ev_type = getattr(ev, "evidence_type", getattr(ev, "type", ""))
            if ev_type == evidence_type:
                if subject is not None:
                    ev_subject = getattr(ev, "subject", None) or (ev.metadata.get("subject") if hasattr(ev, "metadata") else None) or getattr(ev, "location", None)
                    if ev_subject is not None and ev_subject != subject:
                        continue
                return ev
        return None

    def get_evidence_by_type(self, evidence_type: str, subject: Optional[str] = None) -> List[Evidence]:
        """
        Retrieves all evidence records matching the exact evidence_type and optional subject.
        """
        matches = []
        for ev in self.evidence.values():
            ev_type = getattr(ev, "evidence_type", getattr(ev, "type", ""))
            if ev_type == evidence_type:
                if subject is not None:
                    ev_subject = getattr(ev, "subject", None) or (ev.metadata.get("subject") if hasattr(ev, "metadata") else None) or getattr(ev, "location", None)
                    if ev_subject is not None and ev_subject != subject:
                        continue
                matches.append(ev)
        return matches

