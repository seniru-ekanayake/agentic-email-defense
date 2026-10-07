"""
Forensic Ledger & Evidence Grounding Engine for FishingMails.
Implements the core anti-hallucination primitives:
- Real Evidence records (E-xxx) with OBSERVED / INFERRED / CLAIMED / UNKNOWN status
- Hypothesis Lifecycle Management (FACT vs HYPOTHESIS vs INFERENCE vs UNKNOWN)
- Decision Trace (#D-xxx) with observed facts, rationale, actions, and impact
- Tool Execution records with scrubbed credentials, raw and normalized outputs
- "What Actually Happened?" Forensic Audit View
- "Claim vs Evidence" Validation View
- Structured 8-question explanation quality engine
- Risk Score Provenance ledger
- Real measured resource telemetry
"""

import uuid
import datetime
import hashlib
from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class EvidenceStatus(str, Enum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    CLAIMED = "CLAIMED"
    UNKNOWN = "UNKNOWN"


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class HypothesisStatus(str, Enum):
    OPEN = "OPEN"
    SUPPORTED = "SUPPORTED"
    REJECTED = "REJECTED"
    UNRESOLVED = "UNRESOLVED"


class HypothesisCategory(str, Enum):
    FACT = "FACT"
    HYPOTHESIS = "HYPOTHESIS"
    INFERENCE = "INFERENCE"
    UNKNOWN = "UNKNOWN"


class EvidenceItem(BaseModel):
    evidence_id: str = Field(default_factory=lambda: f"E-{uuid.uuid4().hex[:4].upper()}")
    type: str  # MIME_HEADER, UNICODE_OBFUSCATION, URL_PARSER, DNS_RECORD, REPUTATION, etc.
    value: str
    source: str  # MimeParser, UnicodeAnalyzer, Quad9DoH, URLhaus, SandboxEngine, etc.
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    status: EvidenceStatus = EvidenceStatus.OBSERVED
    metadata: Dict[str, Any] = Field(default_factory=dict)


class HypothesisRecord(BaseModel):
    hypothesis_id: str = Field(default_factory=lambda: f"H-{uuid.uuid4().hex[:4].upper()}")
    statement: str
    status: HypothesisStatus = HypothesisStatus.OPEN
    category: HypothesisCategory = HypothesisCategory.HYPOTHESIS
    evidence_ids: List[str] = Field(default_factory=list)
    updated_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class DecisionRecord(BaseModel):
    decision_id: str = Field(default_factory=lambda: f"D-{uuid.uuid4().hex[:4].upper()}")
    observed: str
    evidence_ids: List[str] = Field(default_factory=list)
    decision: str
    action: str
    reason: str
    result: str
    impact: str
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    # The 8 Mandatory Provenance Questions:
    trigger_evidence_ids: List[str] = Field(default_factory=list)
    hypothesis_tested: Optional[str] = None
    alternatives_considered: List[str] = Field(default_factory=list)
    tool_selected_rationale: str = ""
    inputs_rationale: str = ""
    result_observed: str = ""
    belief_state_impact: str = ""
    next_planned_action: str = ""
    planner_type: str = "RULE"
    model: Optional[str] = None
    reasoning_steps: List[str] = Field(default_factory=list)
    reasoning_trace: Optional[str] = None
    llm_proposal: Optional[Dict[str, Any]] = None
    override_reason: Optional[str] = None


class ToolExecutionRecord(BaseModel):
    execution_id: str = Field(default_factory=lambda: f"tool-run-{uuid.uuid4().hex[:6]}")
    tool_name: str
    status: str = "COMPLETED"  # RUNNING, COMPLETED, FAILED
    input_parameters: Dict[str, Any] = Field(default_factory=dict)
    started_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    completed_at: Optional[str] = None
    duration_ms: float = 0.0
    result_summary: str = ""
    raw_response: str = ""
    normalized_response: Dict[str, Any] = Field(default_factory=dict)
    evidence_created: List[str] = Field(default_factory=list)
    source: str = "InternalEngine"
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    error: Optional[str] = None


class ClaimEvidenceItem(BaseModel):
    claim: str
    evidence_ids: List[str] = Field(default_factory=list)
    source: str
    execution: str
    confidence: ConfidenceLevel
    status: str = "SUPPORTED"  # SUPPORTED, NOT_SUPPORTED, UNKNOWN


class ForensicAuditRecord(BaseModel):
    """Answers: What Actually Happened? Grounded strictly in real operations."""
    files_read: List[Dict[str, Any]] = Field(default_factory=list)
    tools_executed: List[Dict[str, Any]] = Field(default_factory=list)
    network_requests: List[Dict[str, Any]] = Field(default_factory=list)
    database_queries: List[Dict[str, Any]] = Field(default_factory=list)
    llm_calls: List[Dict[str, Any]] = Field(default_factory=list)
    sandbox_executions: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_created: List[str] = Field(default_factory=list)
    actions_executed: List[Dict[str, Any]] = Field(default_factory=list)


class RiskDeltaItem(BaseModel):
    component: str
    delta: float
    reason: str
    evidence_id: Optional[str] = None
    resulting_score: float


class RiskScoreProvenance(BaseModel):
    baseline_score: float = 0.0
    final_score: float = 0.0
    adjustments: List[RiskDeltaItem] = Field(default_factory=list)


class VerdictExplanation(BaseModel):
    """Fulfills Requirement 21: Explanation Quality (The 8 Mandatory Questions)."""
    what_did_we_observe: List[str] = Field(default_factory=list)
    what_does_it_mean: str = ""
    what_evidence_supports_it: List[str] = Field(default_factory=list)
    what_did_we_investigate: List[str] = Field(default_factory=list)
    what_did_we_not_investigate: List[str] = Field(default_factory=list)
    what_remains_unknown: List[str] = Field(default_factory=list)
    why_did_the_risk_score_change: List[str] = Field(default_factory=list)
    what_should_the_analyst_do_next: List[str] = Field(default_factory=list)


class ResourceTelemetry(BaseModel):
    execution_time_seconds: float = 0.0
    tool_calls_count: int = 0
    tokens_input: int = 0
    tokens_output: int = 0
    llm_model: Optional[str] = None
    llm_provider: Optional[str] = None
    api_latency_ms: float = 0.0
    network_calls_count: int = 0
    evidence_items_count: int = 0
    hypotheses_count: int = 0
    decisions_count: int = 0
    errors_count: int = 0
    retries_count: int = 0
    estimated_cost_usd: float = 0.0


class EvidenceGraphNode(BaseModel):
    id: str
    label: str
    type: str
    value: str
    source: str
    timestamp: str
    confidence: str
    status: str
    properties: Dict[str, Any] = Field(default_factory=dict)


class EvidenceGraphEdge(BaseModel):
    source: str
    target: str
    relation: str


class EvidenceGraph(BaseModel):
    nodes: List[EvidenceGraphNode] = Field(default_factory=list)
    edges: List[EvidenceGraphEdge] = Field(default_factory=list)


class AgentDecisionState(BaseModel):
    """Requirement 10: Dynamic Agent Decision Panel."""
    current_objective: str
    evidence_considered_count: int = 0
    tools_available_count: int = 5
    tools_executed_count: int = 0
    tools_remaining_count: int = 0
    current_hypothesis: str = "Awaiting input payload"
    next_action: str = "Initialize parser"
    reason: str = "Begin triage pipeline"
    expected_information_gain: str = "High"
    risk_level: str = "Low"
    timeout_remaining: str = "02:00 remaining"
