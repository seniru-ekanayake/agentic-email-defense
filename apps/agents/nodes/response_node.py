"""
Agent Node 6: Response Planning & Human-in-the-Loop Node.
Formulates defensive action proposals, executes safe automated tools,
and generates approval tokens for high-risk actions under tenant autonomy policy.
"""

import logging
from typing import Dict, Any, List, Optional

from packages.schemas.python.models import SecurityState, ToolProposal
from apps.agents.core.tool_registry import ToolRegistry

logger = logging.getLogger("ResponseNode")


class ResponseNode:
    def __init__(self, tool_registry: Optional[ToolRegistry] = None):
        self.tool_registry = tool_registry or ToolRegistry()

    def execute(self, state: SecurityState) -> SecurityState:
        logger.info("ResponseNode executing...")

        tenant_id = state.get("tenant_id", "default-tenant")
        autonomy_level = state.get("autonomy_level", 1)  # Default Level 1 (Recommend)
        email_dict = state.get("email_representation", {})
        message_id = email_dict.get("message_id", "msg-unknown")
        target_user = email_dict.get("recipients", [{}])[0].get("address", "user@corp")

        # 1. Formulate Defensive Proposals Grounded in Evidence
        proposals: List[ToolProposal] = []
        evidence_items = state.get("evidence", [])
        scores = state.get("scores", {})
        severity = scores.get("severity", "LOW")
        overall_risk = scores.get("overall_risk_score", 0.0)

        has_rendering_exploit = any("RENDERING_EXPLOIT" in str(e) or "search-ms" in str(e) or "file:" in str(e) for e in evidence_items)
        has_forced_callout = any("FORCED_CALLOUT" in str(e) or "Forced UNC/SMB" in str(e) for e in evidence_items)
        has_phish = any("Deceptive link" in str(e) or "ACTIVE_SCRIPTING" in str(e) for e in evidence_items)
        has_obfuscation = any("UNICODE" in str(e) or "HOMOGLYPH" in str(e) for e in evidence_items)
        auth_failed = any("SPF/DMARC failure" in str(e) or "Sender Spoofing" in str(e) for e in evidence_items)


        # Propose quarantine only if high risk, rendering exploit, or active phishing
        if severity in ["HIGH", "CRITICAL"] or has_rendering_exploit or (has_phish and overall_risk >= 50):
            proposals.append(
                ToolProposal(
                    tool_name="quarantine_email",
                    parameters={"message_id": message_id, "mailbox": target_user},
                    reasoning="Quarantine malicious email to prevent further rendering or user interaction."
                )
            )

        # Propose session revocation ONLY if active forced callout / NTLM relay or credential theft is observed
        if has_forced_callout:
            proposals.append(
                ToolProposal(
                    tool_name="revoke_session",
                    parameters={"user_id": target_user, "session_id": "active-owa-session"},
                    reasoning="Revoke active sessions to prevent NTLM/cookie relay exploitation."
                )
            )

        # Always safe informational query
        if has_obfuscation or has_phish or auth_failed or overall_risk > 30:
            sender_domain = email_dict.get("sender", {}).get("domain", "")
            if sender_domain and not sender_domain.endswith(".invalid") and not sender_domain.endswith(".example"):
                proposals.append(
                    ToolProposal(
                        tool_name="search_mailbox_history",
                        parameters={"query": sender_domain, "days_back": 14},
                        reasoning=f"Search historical mailboxes for related campaign activity from sender domain {sender_domain}."
                    )
                )

        if not proposals:
            proposals.append(
                ToolProposal(
                    tool_name="create_soc_ticket",
                    parameters={"title": f"Logged email inspection from {email_dict.get('sender', {}).get('address')}", "severity": "LOW"},
                    reasoning="Log inspection record for low-risk/benign email delivery."
                )
            )

        state["proposed_tools"] = [p.model_dump() for p in proposals]
        state.setdefault("executed_tools", [])
        state.setdefault("pending_approvals", [])


        # 2. Process proposals through ToolRegistry safety gates
        for prop in proposals:
            result = self.tool_registry.execute_proposal(
                tenant_id=tenant_id,
                proposal=prop,
                autonomy_level=autonomy_level
            )

            if result.executed:
                state["executed_tools"].append(result.model_dump())
            elif result.requires_human_approval:
                state["pending_approvals"].append({
                    "tool_name": prop.tool_name,
                    "parameters": prop.parameters,
                    "reasoning": prop.reasoning,
                    "approval_token": result.approval_token,
                    "risk_level": "HIGH" if prop.tool_name == "revoke_session" else "MEDIUM"
                })

        # Attach recommended actions to incident report
        if state.get("incident_report"):
            state["incident_report"]["recommended_actions"] = [
                {"action": p.tool_name, "reasoning": p.reasoning, "requires_approval": any(pa.get("tool_name") == p.tool_name for pa in state["pending_approvals"])}
                for p in proposals
            ]
            state["incident_report"]["pending_approvals"] = state["pending_approvals"]

        logger.info(f"ResponseNode completed. Executed: {len(state['executed_tools'])}, Held for Human Approval: {len(state['pending_approvals'])}")
        return state
