"""
ResponsePolicyEngine: Enforces multi-tier tenant autonomy levels, emergency killswitches,
risk-based policy gates, rate limits, and immutable response audit logs.
"""

import uuid
import datetime
import logging
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from packages.schemas.python.models import (
    ToolProposal,
    ToolExecutionResult,
    RiskLevel,
    ApprovalRequirement
)
from apps.agents.core.tool_registry import ToolRegistry, AuditRecord

logger = logging.getLogger("ResponsePolicyEngine")


class TenantResponsePolicy(BaseModel):
    tenant_id: str
    autonomy_level: int = 1  # 0=Observe, 1=Recommend, 2=Human Approved, 3=Policy Auto, 4=Autonomous
    emergency_killswitch_active: bool = False
    allowed_auto_actions: List[str] = Field(default_factory=lambda: ["search_mailbox_history"])
    max_actions_per_hour: int = 50
    require_mfa_for_critical: bool = True


class ResponsePolicyEngine:
    """
    Evaluates agent-proposed response actions against tenant-specific safety policies.
    """

    def __init__(self, tool_registry: Optional[ToolRegistry] = None):
        self.tool_registry = tool_registry or ToolRegistry()
        self._tenant_policies: Dict[str, TenantResponsePolicy] = {}
        self._action_counts: Dict[str, int] = {}
        self._audit_records: List[AuditRecord] = []

    def set_tenant_policy(self, policy: TenantResponsePolicy):
        self._tenant_policies[policy.tenant_id] = policy
        logger.info(f"Updated policy for tenant '{policy.tenant_id}': Autonomy Level={policy.autonomy_level}")

    def get_tenant_policy(self, tenant_id: str) -> TenantResponsePolicy:
        if tenant_id not in self._tenant_policies:
            self._tenant_policies[tenant_id] = TenantResponsePolicy(tenant_id=tenant_id)
        return self._tenant_policies[tenant_id]

    def evaluate_and_execute(
        self,
        tenant_id: str,
        proposal: ToolProposal,
        caller_role: str = "AGENT_RESPONSE_ENGINE"
    ) -> ToolExecutionResult:
        """
        Policy gate enforcing autonomy levels and killswitches.
        """
        policy = self.get_tenant_policy(tenant_id)
        audit_id = str(uuid.uuid4())

        # 1. Emergency Killswitch Check
        if policy.emergency_killswitch_active:
            logger.error(f"[KILLSWITCH ACTIVE] Refusing execution of '{proposal.tool_name}' for tenant '{tenant_id}'.")
            return ToolExecutionResult(
                tool_name=proposal.tool_name,
                success=False,
                executed=False,
                error=f"Emergency killswitch is ACTIVE for tenant {tenant_id}. All actions halted.",
                audit_id=audit_id
            )

        # 2. Autonomy Level 0 (Observe Only)
        if policy.autonomy_level == 0:
            logger.info(f"[AUTONOMY LEVEL 0] Tool '{proposal.tool_name}' logged for observation only.")
            return ToolExecutionResult(
                tool_name=proposal.tool_name,
                success=True,
                executed=False,
                output={"status": "OBSERVE_ONLY", "reason": "Tenant configured for Autonomy Level 0 (Observe)."},
                audit_id=audit_id
            )

        # 3. Check rate limits
        count = self._action_counts.get(tenant_id, 0)
        if count >= policy.max_actions_per_hour:
            logger.warning(f"[RATE LIMIT EXCEEDED] Tenant '{tenant_id}' reached hourly action limit ({policy.max_actions_per_hour}).")
            return ToolExecutionResult(
                tool_name=proposal.tool_name,
                success=False,
                executed=False,
                error="Tenant hourly automated action rate limit exceeded.",
                audit_id=audit_id
            )

        # 4. Delegate to ToolRegistry with tenant autonomy level
        result = self.tool_registry.execute_proposal(
            tenant_id=tenant_id,
            proposal=proposal,
            autonomy_level=policy.autonomy_level,
            caller_role=caller_role
        )

        if result.executed:
            self._action_counts[tenant_id] = count + 1

        return result

    def authorize_action(
        self,
        approval_token: str,
        approver_user_id: str
    ) -> ToolExecutionResult:
        """
        Executes an action held for explicit human approval.
        """
        return self.tool_registry.approve_and_execute(
            approval_token=approval_token,
            approver_user_id=approver_user_id
        )

    def trigger_emergency_killswitch(self, tenant_id: str, enabled: bool = True):
        """Toggles the emergency response killswitch for a tenant."""
        policy = self.get_tenant_policy(tenant_id)
        policy.emergency_killswitch_active = enabled
        logger.warning(f"[EMERGENCY KILLSWITCH] Tenant '{tenant_id}' killswitch set to: {enabled}")
