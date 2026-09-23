"""
Agent Node 2: Email Analysis & Sandbox Observation Node.
Combines deterministic MIME/HTML parsing with isolated Playwright sandbox behavioral analysis.
"""

import logging
from typing import Dict, Any

from packages.schemas.python.models import SecurityState, EmailAttackRepresentation
from apps.sandbox.src.sandbox_runner import SandboxRunner

logger = logging.getLogger("EmailAnalysisNode")


class EmailAnalysisNode:
    def __init__(self):
        self.sandbox_runner = SandboxRunner()

    def execute(self, state: SecurityState) -> SecurityState:
        logger.info(f"EmailAnalysisNode executing for message: {state.get('email_representation', {}).get('message_id')}")
        
        email_dict = state.get("email_representation", {})
        if not email_dict:
            state.setdefault("errors", []).append("Email representation missing in EmailAnalysisNode.")
            return state

        email_rep = EmailAttackRepresentation(**email_dict)

        # Run Sandbox Behavioral Observation
        telemetry = self.sandbox_runner.run_safe_observation(email_rep)
        state["sandbox_telemetry"] = telemetry.model_dump()

        # Extract Evidence
        if not telemetry.is_benign:
            for anomaly in telemetry.rendering_anomalies:
                state["evidence"].append({
                    "stage": "SANDBOX_BEHAVIOR",
                    "type": "RENDERING_ANOMALY",
                    "detail": anomaly
                })
            for dest in telemetry.forced_callout_destinations:
                state["evidence"].append({
                    "stage": "SANDBOX_BEHAVIOR",
                    "type": "FORCED_CALLOUT",
                    "detail": f"Forced UNC/SMB callout to {dest}"
                })
            for ssrf in telemetry.ssrf_attempts:
                state["evidence"].append({
                    "stage": "SANDBOX_BEHAVIOR",
                    "type": "SSRF_ATTEMPT",
                    "detail": f"Blocked attempt to access private/internal target {ssrf}"
                })

        for ind in email_rep.exploit_indicators:
            state["evidence"].append({
                "stage": "STATIC_ANALYSIS",
                "type": ind.indicator_type,
                "detail": ind.evidence,
                "cve": ind.target_cve
            })

        logger.info(f"EmailAnalysisNode completed. Extracted {len(state['evidence'])} evidence items.")
        return state
