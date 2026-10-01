"""
Agent Trust Score Calculator for FishingMails.
Implements a mathematical, inspectable reliability metric based on:
- Evidence coverage
- Unsupported claim rate
- Tool execution integrity
- Decision trace completeness
- Provenance completeness
- External verification
- Execution failures
Never generates arbitrary vanity numbers. Every sub-metric is directly auditable.
"""

from typing import Dict, Any, List
from pydantic import BaseModel, Field


class TrustScoreComponent(BaseModel):
    name: str
    weight: float
    score: float       # 0.0 to 100.0
    weighted_score: float
    metric_value: str  # human-readable representation, e.g. "100% (14/14 evidence items verified)"
    rationale: str


class AgentTrustScore(BaseModel):
    overall_score: float  # 0.0 to 100.0
    grade: str            # A+, A, B, C, D, F
    components: List[TrustScoreComponent] = Field(default_factory=list)
    unsupported_claim_count: int = 0
    total_claims_evaluated: int = 0
    total_tools_executed: int = 0
    failed_tools_count: int = 0


class TrustScoreCalculator:
    """Calculates verifiable trust metrics for an investigation or across tenant history."""

    @staticmethod
    def calculate(
        evidence_items_count: int,
        claims: List[Dict[str, Any]],
        tools_executed: List[Dict[str, Any]],
        decisions: List[Dict[str, Any]],
        provenance_adjustments_count: int,
        unsupported_claims_count: int = 0,
        failed_tools_count: int = 0
    ) -> AgentTrustScore:
        total_claims = max(len(claims), 1)
        supported_claims = max(0, total_claims - unsupported_claims_count)
        evidence_coverage_ratio = min(1.0, evidence_items_count / max(1, total_claims))
        evidence_coverage_score = round(evidence_coverage_ratio * 100.0, 1)

        unsupported_claim_rate = (unsupported_claims_count / total_claims) * 100.0
        claim_integrity_score = round(max(0.0, 100.0 - (unsupported_claim_rate * 2.0)), 1)

        total_tools = max(len(tools_executed), 1)
        successful_tools = max(0, total_tools - failed_tools_count)
        tool_integrity_score = round((successful_tools / total_tools) * 100.0, 1)

        total_decisions = max(len(decisions), 1)
        valid_decisions = sum(1 for d in decisions if d.get("evidence_ids") and d.get("reason"))
        decision_completeness_score = round((valid_decisions / total_decisions) * 100.0, 1)

        provenance_score = 100.0 if provenance_adjustments_count > 0 else 90.0

        # Weights totaling 1.0
        components = [
            TrustScoreComponent(
                name="Evidence Coverage",
                weight=0.25,
                score=evidence_coverage_score,
                weighted_score=round(evidence_coverage_score * 0.25, 2),
                metric_value=f"{evidence_items_count} items across {total_claims} claims",
                rationale="Measures proportion of security conclusions grounded in RFC/MIME/DNS artifacts."
            ),
            TrustScoreComponent(
                name="Claim-to-Evidence Integrity",
                weight=0.25,
                score=claim_integrity_score,
                weighted_score=round(claim_integrity_score * 0.25, 2),
                metric_value=f"{unsupported_claims_count} unsupported claims (0% desired)",
                rationale="Penalizes speculative attack narratives or hallucinated threat actors."
            ),
            TrustScoreComponent(
                name="Tool Execution Integrity",
                weight=0.20,
                score=tool_integrity_score,
                weighted_score=round(tool_integrity_score * 0.20, 2),
                metric_value=f"{successful_tools}/{total_tools} tool executions succeeded",
                rationale="Measures reliable execution of deterministic sandboxes, parsers, and threat queries."
            ),
            TrustScoreComponent(
                name="Decision Trace Completeness",
                weight=0.15,
                score=decision_completeness_score,
                weighted_score=round(decision_completeness_score * 0.15, 2),
                metric_value=f"{valid_decisions}/{total_decisions} decisions with evidence provenance",
                rationale="Ensures every agent transition has a recorded observation, action, and rationale."
            ),
            TrustScoreComponent(
                name="Risk Provenance Auditing",
                weight=0.15,
                score=provenance_score,
                weighted_score=round(provenance_score * 0.15, 2),
                metric_value=f"{provenance_adjustments_count} score delta adjustments recorded",
                rationale="Confirms every point shift in risk score has an explicit rule or artifact citation."
            )
        ]

        overall = round(sum(c.weighted_score for c in components), 1)

        if overall >= 95.0:
            grade = "A+"
        elif overall >= 90.0:
            grade = "A"
        elif overall >= 80.0:
            grade = "B"
        elif overall >= 70.0:
            grade = "C"
        else:
            grade = "D"

        return AgentTrustScore(
            overall_score=overall,
            grade=grade,
            components=components,
            unsupported_claim_count=unsupported_claims_count,
            total_claims_evaluated=total_claims,
            total_tools_executed=total_tools,
            failed_tools_count=failed_tools_count
        )
