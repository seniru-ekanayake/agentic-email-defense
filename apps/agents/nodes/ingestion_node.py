"""
Agent Node 1: Ingestion & Triage Node.
Normalizes incoming email/logs, evaluates data privacy boundary, and sets up SecurityState.
"""

import logging
from typing import Dict, Any

from packages.schemas.python.models import SecurityState, DataClassification
from packages.email_parser.src.mime_parser import MimeParser
from apps.agents.core.data_classification import DataClassificationEngine

logger = logging.getLogger("IngestionNode")


class IngestionNode:
    def __init__(self):
        self.parser = MimeParser()
        self.classification_engine = DataClassificationEngine()

    def execute(self, state: SecurityState) -> SecurityState:
        logger.info(f"IngestionNode executing for tenant: {state.get('tenant_id')}")
        
        raw_eml = state.get("raw_eml")
        email_rep_dict = state.get("email_representation")

        if raw_eml:
            if isinstance(raw_eml, str):
                raw_bytes = raw_eml.encode("utf-8")
            else:
                raw_bytes = raw_eml
            email_rep = self.parser.parse_eml(raw_bytes)
            state["email_representation"] = email_rep.model_dump()
        elif not email_rep_dict:
            state.setdefault("errors", []).append("No email payload provided in state.")
            return state

        # Evaluate Data Classification
        payload = state["email_representation"]
        classification = self.classification_engine.classify_payload(payload)
        state["data_classification"] = classification.value

        # Initialize collections
        state.setdefault("evidence", [])
        state.setdefault("hypotheses", [])
        state.setdefault("telemetry", [])
        state.setdefault("proposed_tools", [])
        state.setdefault("executed_tools", [])
        state.setdefault("pending_approvals", [])

        state["evidence"].append({
            "stage": "INGESTION",
            "summary": f"Email successfully normalized with classification {classification.value}.",
            "message_id": payload.get("message_id")
        })

        return state
