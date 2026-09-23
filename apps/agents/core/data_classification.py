"""
DataClassificationEngine: Mandatory Data Privacy Boundary.
Enforces that CONFIDENTIAL / RESTRICTED data never silently leaves to third-party LLMs.
Maintains full audit trails of classification and routing decisions.
"""

import datetime
import logging
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from packages.schemas.python.models import DataClassification

logger = logging.getLogger("DataClassificationEngine")


class PrivacyDecisionAudit(BaseModel):
    audit_id: str
    tenant_id: str
    classification: DataClassification
    allowed_providers: List[str]
    selected_provider: str
    model_used: str
    policy_reason: str
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class DataClassificationEngine:
    """
    Evaluates payloads, assigns classification, and determines permitted execution paths.
    """
    
    # Sensitive keywords / patterns for deterministic heuristic classification
    CONFIDENTIAL_INDICATORS = [
        "confidential", "secret", "private key", "password", "ssn",
        "proprietary", "internal only", "financial statement", "salary",
        "token", "api_key", "bearer "
    ]

    def __init__(self):
        self.audit_log: List[PrivacyDecisionAudit] = []

    def classify_payload(self, content: Dict[str, Any], explicit_classification: Optional[str] = None) -> DataClassification:
        """
        Classifies an email or telemetry payload.
        Explicit classification takes precedence if valid; otherwise scans heuristics.
        """
        if explicit_classification:
            try:
                return DataClassification(explicit_classification.upper())
            except ValueError:
                pass

        # Text heuristic scanning
        text_content = ""
        if isinstance(content, dict):
            body = content.get("body", {})
            text_content += (body.get("text_plain") or "") + " " + (body.get("text_html") or "")
            for header_k, header_v in content.get("headers", {}).items():
                text_content += f" {header_k}: {header_v}"

        lower_text = text_content.lower()
        if any(indicator in lower_text for indicator in ["restricted", "top secret", "private key"]):
            return DataClassification.RESTRICTED
        if any(indicator in lower_text for indicator in self.CONFIDENTIAL_INDICATORS):
            return DataClassification.CONFIDENTIAL
        
        return DataClassification.INTERNAL

    def evaluate_privacy_policy(
        self,
        tenant_id: str,
        classification: DataClassification,
        requested_provider: str = "OpenRouterProvider"
    ) -> PrivacyDecisionAudit:
        """
        Enforces tenant data privacy boundary:
        - PUBLIC / INTERNAL: Permitted to use OpenRouter.
        - CONFIDENTIAL / RESTRICTED: Must default to local LLM or deterministic analysis.
        """
        import uuid
        audit_id = str(uuid.uuid4())

        if classification in [DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED]:
            allowed = ["LocalOllamaProvider", "DeterministicOnly"]
            selected = "LocalOllamaProvider"
            model = "ollama/local-privacy-safe"
            reason = f"Data classified as {classification.value}. Routing to local LLM to prevent external leakage."
        else:
            allowed = ["OpenRouterProvider", "LocalOllamaProvider", "DeterministicOnly"]
            selected = requested_provider
            model = "openrouter/free"
            reason = f"Data classified as {classification.value}. Permitted for external reasoning."

        audit_entry = PrivacyDecisionAudit(
            audit_id=audit_id,
            tenant_id=tenant_id,
            classification=classification,
            allowed_providers=allowed,
            selected_provider=selected,
            model_used=model,
            policy_reason=reason
        )

        self.audit_log.append(audit_entry)
        logger.info(f"[PRIVACY AUDIT] Tenant: {tenant_id} | Class: {classification.value} | Provider: {selected} | Reason: {reason}")
        return audit_entry
