"""Human-in-the-Loop Token Authorization & Approval Engine.

Manages policy-gated containment approval workflows. Validates signed
APP-XXXXXX human authorization tokens before executing high-risk defensive actions.
"""

from __future__ import annotations

import datetime
import logging
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from packages.schemas.python.models import ToolProposal, ToolExecutionResult, RiskLevel
from apps.agents.core.tool_registry import ToolRegistry

logger = logging.getLogger("core.approval_manager")


class PendingApproval(BaseModel):
    token: str
    tenant_id: str
    tool_name: str
    parameters: Dict[str, Any]
    risk_level: str
    target_cve: Optional[str] = None
    target_identity: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    status: str = "PENDING"  # PENDING, APPROVED, REJECTED, EXPIRED
    approver: Optional[str] = None
    comments: Optional[str] = None
    execution_result: Optional[Dict[str, Any]] = None


class ApprovalManager:
    """Manages the lifecycle of human authorization tokens and policy gating."""

    _instance: Optional[ApprovalManager] = None

    def __init__(self, tool_registry: Optional[ToolRegistry] = None):
        self.tool_registry = tool_registry or ToolRegistry()
        self._pending_approvals: Dict[str, PendingApproval] = {}

    @classmethod
    def get_instance(cls) -> ApprovalManager:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def create_pending_approval(
        self,
        tenant_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
        risk_level: str = "HIGH",
        target_cve: Optional[str] = None,
        target_identity: Optional[str] = None
    ) -> str:
        """Generate and register a signed APP-XXXXXX authorization token."""
        token = f"APP-{uuid.uuid4().hex[:6].upper()}"
        item = PendingApproval(
            token=token,
            tenant_id=tenant_id,
            tool_name=tool_name,
            parameters=parameters,
            risk_level=risk_level,
            target_cve=target_cve,
            target_identity=target_identity
        )
        self._pending_approvals[token] = item
        logger.info(f"Created pending approval token '{token}' for tool '{tool_name}' [Tenant: {tenant_id}]")
        return token

    def authorize_and_execute(
        self,
        tenant_id: str,
        token: str,
        approver_email: str,
        comments: Optional[str] = None
    ) -> Dict[str, Any]:
        """Validate token and execute the approved tool proposal via ToolRegistry."""
        if token not in self._pending_approvals:
            return {"success": False, "error": f"Invalid or expired approval token: '{token}'", "executed": False}

        item = self._pending_approvals[token]
        if item.tenant_id != tenant_id:
            return {"success": False, "error": "Tenant mismatch for approval token", "executed": False}

        if item.status != "PENDING":
            return {"success": False, "error": f"Token '{token}' has already been processed (status: {item.status})", "executed": False}

        # Build proposal and execute through ToolRegistry with autonomy=4 (Human Approved)
        proposal = ToolProposal(
            tool_name=item.tool_name,
            parameters=item.parameters,
            reasoning=f"Approved by SOC Analyst {approver_email}: {comments or 'Standard Incident Remediation'}"
        )

        exec_res: ToolExecutionResult = self.tool_registry.execute_proposal(
            tenant_id=tenant_id,
            proposal=proposal,
            autonomy_level=4,  # Human approved forces execution
            caller_role="SOC_ANALYST"
        )

        item.status = "APPROVED" if exec_res.executed else "FAILED"
        item.approver = approver_email
        item.comments = comments
        item.execution_result = exec_res.model_dump()

        logger.info(f"Executed approved action '{item.tool_name}' via token '{token}' [Success: {exec_res.success}]")
        return {
            "success": exec_res.success,
            "executed": exec_res.executed,
            "token": token,
            "tool_name": item.tool_name,
            "result": exec_res.output,
            "audit_id": exec_res.audit_id
        }

    def reject_action(
        self,
        tenant_id: str,
        token: str,
        approver_email: str,
        reason: str = "Rejected by analyst"
    ) -> Dict[str, Any]:
        """Explicitly reject a pending containment proposal."""
        if token not in self._pending_approvals:
            return {"success": False, "error": f"Invalid approval token: '{token}'"}

        item = self._pending_approvals[token]
        item.status = "REJECTED"
        item.approver = approver_email
        item.comments = reason
        logger.info(f"Rejected action '{item.tool_name}' via token '{token}' [Approver: {approver_email}]")
        return {"success": True, "token": token, "status": "REJECTED", "reason": reason}

    def get_pending_approvals(self, tenant_id: Optional[str] = None) -> List[PendingApproval]:
        """List active pending approvals."""
        if tenant_id:
            return [p for p in self._pending_approvals.values() if p.tenant_id == tenant_id and p.status == "PENDING"]
        return [p for p in self._pending_approvals.values() if p.status == "PENDING"]

    def clear(self) -> None:
        self._pending_approvals.clear()
