"""
Python Agent Service Entrypoint.
Initializes the LLMGateway, DataClassificationEngine, ToolRegistry,
and starts the LangGraph worker listener.
"""

import os
import sys
import logging
from typing import Dict, Any

# Ensure root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from apps.agents.core.llm_gateway import LLMGateway
from apps.agents.core.data_classification import DataClassificationEngine
from apps.agents.core.tool_registry import ToolRegistry

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("AgentService")


class AgentService:
    def __init__(self):
        logger.info("Initializing AgentService...")
        self.gateway = LLMGateway()
        self.classification_engine = DataClassificationEngine()
        self.tool_registry = ToolRegistry()
        logger.info("AgentService initialized successfully.")

    def process_triage(self, tenant_id: str, email_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Triage pipeline entrypoint."""
        # 1. Classify payload
        classification = self.classification_engine.classify_payload(email_payload)
        privacy_decision = self.classification_engine.evaluate_privacy_policy(tenant_id, classification)
        
        # 2. Select appropriate provider
        provider = self.gateway.get_provider(is_confidential=(classification != "PUBLIC" and classification != "INTERNAL"))
        
        logger.info(f"Triage processed: Tenant={tenant_id}, Classification={classification.value}, Provider={privacy_decision.selected_provider}")
        return {
            "status": "TRIAGE_COMPLETE",
            "classification": classification.value,
            "provider_used": privacy_decision.selected_provider,
            "audit_id": privacy_decision.audit_id
        }


if __name__ == "__main__":
    service = AgentService()
    test_payload = {
        "headers": {"Subject": "Urgent Invoice Attached"},
        "body": {"text_plain": "Please review immediately."}
    }
    result = service.process_triage("tenant-demo", test_payload)
    print("Service Startup Test Result:", result)
