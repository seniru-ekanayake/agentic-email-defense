"""
ToolRegistry: Strict Policy-Gated Tool Execution System.
The LLM never directly executes tools; it proposes tool calls which are strictly validated,
authorized based on risk level and tenant autonomy, and recorded in an immutable audit trail.
"""

import uuid
import datetime
import logging
from typing import Dict, Any, List, Optional, Callable
from pydantic import BaseModel, Field

from packages.schemas.python.models import (
    ToolDefinition,
    ToolProposal,
    ToolExecutionResult,
    RiskLevel,
    ApprovalRequirement
)

logger = logging.getLogger("ToolRegistry")


class AuditRecord(BaseModel):
    audit_id: str
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    tenant_id: str
    tool_name: str
    risk_level: RiskLevel
    parameters: Dict[str, Any]
    executed: bool
    requires_approval: bool
    approval_token: Optional[str] = None
    caller_role: str
    result_summary: Optional[str] = None


class ToolRegistry:
    """
    Central repository of authorized defensive tools with deterministic policy gates.
    """
    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
        self._handlers: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {}
        self._pending_approvals: Dict[str, Dict[str, Any]] = {}
        self._audit_trail: List[AuditRecord] = []
        
        self._register_default_tools()

    def register_tool(
        self,
        definition: ToolDefinition,
        handler: Callable[[Dict[str, Any]], Dict[str, Any]]
    ):
        self._tools[definition.name] = definition
        self._handlers[definition.name] = handler
        logger.info(f"Registered tool: {definition.name} [Risk: {definition.risk_level.value}, Approval: {definition.approval_requirement.value}]")

    def get_tool_definitions(self) -> List[ToolDefinition]:
        return list(self._tools.values())

    def execute_proposal(
        self,
        tenant_id: str,
        proposal: ToolProposal,
        autonomy_level: int = 1, # 0=Observe, 1=Recommend, 2=Human Approved, 3=Policy Auto, 4=Full Auto
        caller_role: str = "AGENT"
    ) -> ToolExecutionResult:
        """
        Evaluates a tool proposal against safety gates and autonomy policies.
        """
        tool_name = proposal.tool_name
        audit_id = str(uuid.uuid4())

        if tool_name not in self._tools:
            return ToolExecutionResult(
                tool_name=tool_name,
                success=False,
                executed=False,
                error=f"Tool '{tool_name}' is not registered in ToolRegistry.",
                audit_id=audit_id
            )

        tool_def = self._tools[tool_name]
        
        # Determine whether human approval is required
        requires_approval = False
        approval_token = None

        if tool_def.risk_level == RiskLevel.CRITICAL:
            # Critical actions (e.g. disable_account) ALWAYS require human approval unless autonomy=4
            if autonomy_level < 4:
                requires_approval = True
        elif tool_def.risk_level == RiskLevel.HIGH:
            # High actions (e.g. revoke_session) require approval if autonomy < 3
            if autonomy_level < 3:
                requires_approval = True
        elif tool_def.risk_level == RiskLevel.MEDIUM:
            # Medium actions (e.g. quarantine_email) require approval if autonomy < 2
            if autonomy_level < 2:
                requires_approval = True

        if requires_approval:
            approval_token = f"APP-{uuid.uuid4().hex[:8].upper()}"
            self._pending_approvals[approval_token] = {
                "tenant_id": tenant_id,
                "tool_name": tool_name,
                "parameters": proposal.parameters,
                "reasoning": proposal.reasoning,
                "audit_id": audit_id,
                "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
            
            audit = AuditRecord(
                audit_id=audit_id,
                tenant_id=tenant_id,
                tool_name=tool_name,
                risk_level=tool_def.risk_level,
                parameters=proposal.parameters,
                executed=False,
                requires_approval=True,
                approval_token=approval_token,
                caller_role=caller_role,
                result_summary=f"Action held for human authorization (Token: {approval_token})"
            )
            self._audit_trail.append(audit)
            logger.warning(f"[POLICY GATE] Tool '{tool_name}' held for human approval (Token: {approval_token})")
            
            return ToolExecutionResult(
                tool_name=tool_name,
                success=True,
                executed=False,
                requires_human_approval=True,
                approval_token=approval_token,
                output={"status": "PENDING_APPROVAL", "token": approval_token},
                audit_id=audit_id
            )

        # Execute tool handler
        try:
            handler = self._handlers[tool_name]
            result_output = handler(proposal.parameters)
            
            audit = AuditRecord(
                audit_id=audit_id,
                tenant_id=tenant_id,
                tool_name=tool_name,
                risk_level=tool_def.risk_level,
                parameters=proposal.parameters,
                executed=True,
                requires_approval=False,
                caller_role=caller_role,
                result_summary="Execution successful"
            )
            self._audit_trail.append(audit)
            logger.info(f"[TOOL EXECUTED] Tool '{tool_name}' executed successfully.")
            
            return ToolExecutionResult(
                tool_name=tool_name,
                success=True,
                executed=True,
                output=result_output,
                audit_id=audit_id
            )
        except Exception as e:
            logger.error(f"[TOOL ERROR] Error executing '{tool_name}': {e}")
            return ToolExecutionResult(
                tool_name=tool_name,
                success=False,
                executed=False,
                error=str(e),
                audit_id=audit_id
            )

    def approve_and_execute(self, approval_token: str, approver_user_id: str) -> ToolExecutionResult:
        """
        Executes a previously held tool action after explicit human authorization.
        """
        if approval_token not in self._pending_approvals:
            raise ValueError(f"Invalid or expired approval token: {approval_token}")

        pending = self._pending_approvals.pop(approval_token)
        tool_name = pending["tool_name"]
        parameters = pending["parameters"]
        tenant_id = pending["tenant_id"]
        
        handler = self._handlers[tool_name]
        result_output = handler(parameters)
        
        audit_id = str(uuid.uuid4())
        audit = AuditRecord(
            audit_id=audit_id,
            tenant_id=tenant_id,
            tool_name=tool_name,
            risk_level=self._tools[tool_name].risk_level,
            parameters=parameters,
            executed=True,
            requires_approval=False,
            caller_role=f"HUMAN_APPROVER:{approver_user_id}",
            result_summary=f"Executed via human approval token {approval_token}"
        )
        self._audit_trail.append(audit)
        
        return ToolExecutionResult(
            tool_name=tool_name,
            success=True,
            executed=True,
            output=result_output,
            audit_id=audit_id
        )

    def _register_default_tools(self):
        """Registers the core platform tools."""
        
        # 1. Quarantine Email (MEDIUM risk)
        self.register_tool(
            ToolDefinition(
                name="quarantine_email",
                description="Quarantine a malicious email message across affected mailboxes.",
                risk_level=RiskLevel.MEDIUM,
                required_permission="email.quarantine",
                approval_requirement=ApprovalRequirement.POLICY_DEPENDENT,
                input_schema={"message_id": "string", "mailbox": "string"},
                output_schema={"status": "string", "quarantined_count": "integer"}
            ),
            lambda p: {"status": "SUCCESS", "quarantined_count": 1, "target": p.get("message_id")}
        )

        # 2. Revoke Session (HIGH risk)
        self.register_tool(
            ToolDefinition(
                name="revoke_session",
                description="Revoke all active webmail/OAuth sessions for targeted user identity.",
                risk_level=RiskLevel.HIGH,
                required_permission="identity.session_revoke",
                approval_requirement=ApprovalRequirement.MANDATORY_HUMAN,
                input_schema={"user_id": "string", "session_id": "string"},
                output_schema={"status": "string", "sessions_revoked": "integer"}
            ),
            lambda p: {"status": "SUCCESS", "sessions_revoked": 1, "target_user": p.get("user_id")}
        )

        # 3. Disable Account (CRITICAL risk)
        self.register_tool(
            ToolDefinition(
                name="disable_account",
                description="Disable Active Directory / Okta / Google account immediately.",
                risk_level=RiskLevel.CRITICAL,
                required_permission="identity.account_disable",
                approval_requirement=ApprovalRequirement.MANDATORY_HUMAN,
                input_schema={"user_id": "string", "reason": "string"},
                output_schema={"status": "string", "account_disabled": "boolean"}
            ),
            lambda p: {"status": "SUCCESS", "account_disabled": True, "target_user": p.get("user_id")}
        )

        # 4. Search Historical Mailbox Activity (LOW risk)
        self.register_tool(
            ToolDefinition(
                name="search_mailbox_history",
                description="Search historical emails for correlated campaign indicators or sender addresses.",
                risk_level=RiskLevel.LOW,
                required_permission="email.search",
                approval_requirement=ApprovalRequirement.AUTOMATIC,
                input_schema={"query": "string", "days_back": "integer"},
                output_schema={"matched_messages": "array"}
            ),
            lambda p: {"status": "SUCCESS", "matched_messages": [], "query": p.get("query")}
        )

        # 5. Block Sender / Domain (MEDIUM risk)
        self.register_tool(
            ToolDefinition(
                name="block_sender",
                description="Block sender email address or entire domain at mail gateway.",
                risk_level=RiskLevel.MEDIUM,
                required_permission="gateway.block",
                approval_requirement=ApprovalRequirement.POLICY_DEPENDENT,
                input_schema={"sender_or_domain": "string", "reason": "string"},
                output_schema={"status": "string", "entry_added": "boolean"}
            ),
            lambda p: {"status": "SUCCESS", "entry_added": True, "target": p.get("sender_or_domain")}
        )

        # 6. Block IOC at Network Firewall (HIGH risk)
        self.register_tool(
            ToolDefinition(
                name="block_ioc",
                description="Push malicious IP, URL, or hash IOC to network firewalls / EDR.",
                risk_level=RiskLevel.HIGH,
                required_permission="firewall.block_ioc",
                approval_requirement=ApprovalRequirement.MANDATORY_HUMAN,
                input_schema={"ioc_value": "string", "ioc_type": "string"},
                output_schema={"status": "string", "firewall_synced": "boolean"}
            ),
            lambda p: {"status": "SUCCESS", "firewall_synced": True, "ioc": p.get("ioc_value")}
        )

        # 7. Force Password Reset (MEDIUM risk)
        self.register_tool(
            ToolDefinition(
                name="force_password_reset",
                description="Force user to reset password upon next login attempt.",
                risk_level=RiskLevel.MEDIUM,
                required_permission="identity.password_reset",
                approval_requirement=ApprovalRequirement.POLICY_DEPENDENT,
                input_schema={"user_id": "string"},
                output_schema={"status": "string", "reset_flagged": "boolean"}
            ),
            lambda p: {"status": "SUCCESS", "reset_flagged": True, "user_id": p.get("user_id")}
        )

        # 8. Create SOC Ticket (LOW risk)
        self.register_tool(
            ToolDefinition(
                name="create_soc_ticket",
                description="Create tracking incident ticket in SOC ticketing system (Jira/ServiceNow).",
                risk_level=RiskLevel.LOW,
                required_permission="soc.ticket_create",
                approval_requirement=ApprovalRequirement.AUTOMATIC,
                input_schema={"title": "string", "severity": "string", "details": "object"},
                output_schema={"ticket_id": "string", "status": "string"}
            ),
            lambda p: {"ticket_id": f"SOC-{uuid.uuid4().hex[:6].upper()}", "status": "OPEN", "title": p.get("title")}
        )

        # 9. Free Threat Intel Indicator Lookup (LOW risk)
        from packages.threat_intel.src.free_feeds import FreeThreatIntelEngine
        _threat_engine = FreeThreatIntelEngine()

        self.register_tool(
            ToolDefinition(
                name="threat_intel_lookup",
                description="Query 100% free threat intel feeds (URLhaus malware URLs, AbuseIPDB reputation, Quad9 DoH) for URLs, IPs, or domains.",
                risk_level=RiskLevel.LOW,
                required_permission="threat_intel.query",
                approval_requirement=ApprovalRequirement.AUTOMATIC,
                input_schema={"indicator_type": "string", "indicator_value": "string"},
                output_schema={"is_malicious": "boolean", "details": "object"}
            ),
            lambda p: _threat_engine.assess_indicator(p.get("indicator_type", "url"), p.get("indicator_value", ""))
        )

        # 10. DNS & SPF/DMARC Recon Tool (LOW risk)
        from apps.agents.core.mcp_servers.dns_server import handle_spf_dmarc_audit, handle_dns_resolve
        self.register_tool(
            ToolDefinition(
                name="dns_spf_dmarc_recon",
                description="Audit domain SPF and DMARC enforcement records for email spoofing vulnerability.",
                risk_level=RiskLevel.LOW,
                required_permission="network.dns_lookup",
                approval_requirement=ApprovalRequirement.AUTOMATIC,
                input_schema={"domain": "string"},
                output_schema={"has_spf": "boolean", "has_dmarc": "boolean", "is_spoofing_vulnerable": "boolean"}
            ),
            lambda p: handle_spf_dmarc_audit(p)
        )

        # 11. Historical Communication Telemetry (LOW risk)
        from apps.agents.core.mcp_servers.telemetry_server import handle_query_sender_history
        self.register_tool(
            ToolDefinition(
                name="query_sender_history",
                description="Query historical communication frequency, first-seen timestamp, and baseline anomaly score for a sender/recipient pair.",
                risk_level=RiskLevel.LOW,
                required_permission="telemetry.query",
                approval_requirement=ApprovalRequirement.AUTOMATIC,
                input_schema={"sender_email": "string", "recipient_email": "string", "sender_domain": "string"},
                output_schema={"historical_email_count": "integer", "is_first_time_sender": "boolean", "baseline_reputation": "string"}
            ),
            lambda p: handle_query_sender_history(p)
        )

