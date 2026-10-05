"""
Human-in-the-Loop Token Authorization & Approval Engine.
Manages policy-gated containment approval workflows using cryptographically strong,
HMAC-SHA256 signed, multi-worker persistent approval tokens.
Tokens are tenant-scoped, incident-scoped, action-scoped, time-limited, nonce-based, and single-use.
"""

from __future__ import annotations

import hmac
import hashlib
import json
import secrets
import time
import datetime
import logging
import os
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field

from packages.schemas.python.models import ToolProposal, ToolExecutionResult
from apps.agents.core.tool_registry import ToolRegistry
from apps.agents.core.durable_storage import DurableStorage

logger = logging.getLogger("core.approval_manager")

def get_hmac_secret_key() -> bytes:
    """
    Retrieves and validates the HMAC approval signing secret.
    In PRODUCTION mode:
    - Must be explicitly set via FISHINGMAILS_APPROVAL_HMAC_SECRET.
    - If missing, fails closed with RuntimeError.
    In DEVELOPMENT / TEST / DEMO mode:
    - Defaults to safe development HMAC secret if unset.
    """
    secret = os.getenv("FISHINGMAILS_APPROVAL_HMAC_SECRET", "").strip()
    from apps.agents.core.production_manager import ProductionManager
    if ProductionManager.get_instance().is_production():
        if not secret:
            raise RuntimeError("FATAL SECURITY CONFIGURATION ERROR: FISHINGMAILS_APPROVAL_HMAC_SECRET is required in production.")
        return secret.encode("utf-8")
    if not secret:
        return b"fishingmails-dev-approval-secret-key-v1"
    return secret.encode("utf-8")



class PendingApproval(BaseModel):
    token: str
    tenant_id: str
    incident_id: str = "GLOBAL"
    tool_name: str = Field(default="")
    action_name: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    risk_level: str = "HIGH"
    target_cve: Optional[str] = None
    target_identity: Optional[str] = None
    nonce: str = ""
    expiry_timestamp: Union[float, str] = 0.0
    hmac_signature: str = ""
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    status: str = "PENDING"  # PENDING, CLAIMED, EXECUTED, FAILED, REJECTED, EXPIRED, CONSUMED
    approver: Optional[str] = None
    comments: Optional[str] = None
    execution_result: Optional[Dict[str, Any]] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.tool_name and self.action_name:
            self.tool_name = self.action_name


class ApprovalManager:
    """
    Manages the lifecycle of persistent, cryptographically signed human authorization tokens.
    """

    _instance: Optional[ApprovalManager] = None

    def __init__(self, tool_registry: Optional[ToolRegistry] = None, storage: Optional[DurableStorage] = None):
        self.tool_registry = tool_registry or ToolRegistry()
        self.storage = storage or DurableStorage.get_instance()

    @property
    def secret_key(self) -> bytes:
        return get_hmac_secret_key()

    @classmethod
    def get_instance(cls) -> ApprovalManager:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _compute_hmac(self, tenant_id: str, incident_id: str, tool_name: str, nonce: str, expiry: float) -> str:
        msg = f"{tenant_id}:{incident_id}:{tool_name}:{nonce}:{expiry}"
        return hmac.new(self.secret_key, msg.encode("utf-8"), hashlib.sha256).hexdigest()

    def create_pending_approval(
        self,
        tenant_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
        incident_id: str = "GLOBAL",
        risk_level: str = "HIGH",
        target_cve: Optional[str] = None,
        target_identity: Optional[str] = None,
        ttl_seconds: float = 86400.0  # 24 hour expiry
    ) -> str:
        """
        Generates and persists a cryptographically signed authorization token.
        """
        nonce = secrets.token_hex(16)
        expiry = time.time() + ttl_seconds
        sig = self._compute_hmac(tenant_id, incident_id, tool_name, nonce, expiry)
        
        # Token format: APP-<nonce_short>-<sig_short>
        token = f"APP-{nonce[:8].upper()}-{sig[:8].upper()}"

        item = PendingApproval(
            token=token,
            tenant_id=tenant_id,
            incident_id=incident_id,
            tool_name=tool_name,
            parameters=parameters,
            risk_level=risk_level,
            target_cve=target_cve,
            target_identity=target_identity,
            nonce=nonce,
            expiry_timestamp=expiry,
            hmac_signature=sig,
            status="PENDING"
        )

        # Persist to durable SQLite storage
        self.storage.save_approval_token(item.model_dump())
        logger.info(f"Created signed durable approval token '{token}' for tool '{tool_name}' [Tenant: {tenant_id}, Incident: {incident_id}]")
        return token

    def authorize_and_execute(
        self,
        tenant_id: str,
        token: str,
        approver_email: str,
        comments: Optional[str] = None,
        incident_id: Optional[str] = None,
        action_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Validates HMAC signature, scoping, expiry, and single-use status before executing approved tool.
        """
        token_data = self.storage.get_approval_token(token)
        if not token_data:
            return {"success": False, "error": f"Invalid or unknown approval token: '{token}'", "executed": False}

        item = PendingApproval(**token_data)

        # 1. Scoping Checks
        if item.tenant_id != tenant_id:
            return {"success": False, "error": f"Tenant mismatch for approval token (expected {item.tenant_id}, got {tenant_id})", "executed": False}

        if incident_id and item.incident_id != "GLOBAL" and item.incident_id != incident_id:
            return {"success": False, "error": f"Incident mismatch for approval token (expected {item.incident_id}, got {incident_id})", "executed": False}

        if action_name and item.tool_name != action_name:
            return {"success": False, "error": f"Action mismatch for approval token (expected {item.tool_name}, got {action_name})", "executed": False}

        # 2. Expiry Check
        try:
            exp_time = float(item.expiry_timestamp)
        except (ValueError, TypeError):
            exp_time = 0.0
            
        if time.time() > exp_time:
            if item.status == "PENDING":
                item.status = "EXPIRED"
                self.storage.save_approval_token(item.model_dump())
            return {"success": False, "error": f"Token '{token}' has expired", "executed": False}

        # 3. Cryptographic HMAC Signature Verification
        expected_sig = self._compute_hmac(item.tenant_id, item.incident_id, item.tool_name, item.nonce, exp_time)
        if not hmac.compare_digest(item.hmac_signature, expected_sig):
            return {"success": False, "error": f"Cryptographic signature verification failed for token '{token}' (tampered token)", "executed": False}

        # 4. Status & Atomic Single-Use Check
        if item.status != "PENDING":
            return {"success": False, "error": f"Token '{token}' is invalid or has already been processed / consumed (status: {item.status})", "executed": False}

        if not self.storage.claim_approval_token_atomic(token):
            return {"success": False, "error": f"Token '{token}' was already claimed by a concurrent request.", "executed": False}

        # Status is now CLAIMED in DB, update local item
        item.status = "CLAIMED"
        item.approver = approver_email
        item.comments = comments
        self.storage.save_approval_token(item.model_dump())

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

        # Single-use status update: mark CONSUMED
        item.status = "CONSUMED" if exec_res.executed else "FAILED"
        item.execution_result = exec_res.model_dump()
        self.storage.save_approval_token(item.model_dump())

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
        token_data = self.storage.get_approval_token(token)
        if not token_data:
            return {"success": False, "error": f"Invalid approval token: '{token}'"}

        item = PendingApproval(**token_data)
        if item.tenant_id != tenant_id:
            return {"success": False, "error": "Tenant mismatch for approval token"}

        item.status = "REJECTED"
        item.approver = approver_email
        item.comments = reason
        self.storage.save_approval_token(item.model_dump())
        logger.info(f"Rejected action '{item.tool_name}' via token '{token}' [Approver: {approver_email}]")
        return {"success": True, "token": token, "status": "REJECTED", "reason": reason}

    def get_pending_approvals(self, tenant_id: Optional[str] = None) -> List[PendingApproval]:
        """List active pending approvals from durable storage."""
        records = self.storage.list_pending_approval_tokens(tenant_id)
        return [PendingApproval(**r) for r in records]

    def clear(self) -> None:
        """Clear pending approvals for test isolation."""
        conn = self.storage._get_connection()
        with conn:
            conn.execute("DELETE FROM approval_tokens WHERE tenant_id LIKE 'tenant-stream%' OR tenant_id LIKE 'tenant-test%'")

