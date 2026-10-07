"""
Agent Node: Response planning & human-in-the-loop gating.
Proposals are derived from the computed verdict. Every proposal goes through the ToolRegistry
policy gate; MEDIUM+ risk actions are held behind a signed approval token.
"""

import logging
from typing import List, Optional

from packages.schemas.python.models import SecurityState, ToolProposal
from apps.agents.core.tool_registry import ToolRegistry

logger = logging.getLogger("ResponseNode")


class ResponseNode:
    def __init__(self, tool_registry: Optional[ToolRegistry] = None):
        self.tool_registry = tool_registry or ToolRegistry.get_instance()

    def execute(self, state: SecurityState) -> SecurityState:
        tenant_id = state.get("tenant_id", "default-tenant")
        autonomy_level = state.get("autonomy_level", 1)
        email_dict = state.get("email_representation", {}) or {}
        verdict = state["verdict"]
        message_id = email_dict.get("message_id", "msg-unknown")
        target_user = ((email_dict.get("recipients") or [{}])[0].get("address")) or "unknown"
        sender_domain = (email_dict.get("sender") or {}).get("domain", "")
        evidence_ids = [f.evidence_id for f in verdict.factors]

        proposals: List[ToolProposal] = []
        if verdict.verdict == "MALICIOUS":
            proposals.append(ToolProposal(
                tool_name="quarantine_email",
                parameters={"message_id": message_id, "mailbox": target_user},
                reasoning=f"Verdict MALICIOUS (risk {verdict.risk_score}) based on evidence {', '.join(evidence_ids)}."))
            if verdict.forced_authentication:
                proposals.append(ToolProposal(
                    tool_name="revoke_session",
                    parameters={"user_id": target_user},
                    reasoning="Forced-authentication URI observed; credentials may have been exposed if the message was rendered."))
        if verdict.verdict in ("MALICIOUS", "SUSPICIOUS") and sender_domain:
            proposals.append(ToolProposal(
                tool_name="search_mailbox_history",
                parameters={"query": sender_domain, "days_back": 14},
                reasoning=f"Look for related messages from {sender_domain}."))

        state["proposed_tools"] = [p.model_dump() for p in proposals]
        state["executed_tools"] = []
        state["pending_approvals"] = []
        incident_id = state.get("incident_id") or state.get("workflow_id")

        for prop in proposals:
            result = self.tool_registry.execute_proposal(
                tenant_id=tenant_id, proposal=prop, autonomy_level=autonomy_level, incident_id=incident_id)
            if result.requires_human_approval:
                state["pending_approvals"].append({
                    "tool_name": prop.tool_name,
                    "parameters": prop.parameters,
                    "reasoning": prop.reasoning,
                    "approval_token": result.approval_token,
                    "incident_id": incident_id,
                    "risk_level": self.tool_registry.get_risk_level(prop.tool_name),
                    "error": result.error,
                })
            else:
                state["executed_tools"].append(result.model_dump())

        report = state.get("incident_report")
        if report is not None:
            pending_names = {p["tool_name"] for p in state["pending_approvals"]}
            report["recommended_actions"] = [
                {"action": p.tool_name, "reasoning": p.reasoning, "requires_approval": p.tool_name in pending_names}
                for p in proposals
            ]
            report["pending_approvals"] = state["pending_approvals"]
        return state
