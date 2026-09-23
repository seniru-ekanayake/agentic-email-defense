"""
LangGraph Workflow Orchestrator.
Assembles the typed SecurityState graph connecting Ingestion, Email Analysis,
Vulnerability Research, Exposure Correlation, Investigation, and Response Planning.
"""

import logging
from typing import Dict, Any, Callable

from packages.schemas.python.models import SecurityState
from apps.agents.nodes.ingestion_node import IngestionNode
from apps.agents.nodes.email_analysis_node import EmailAnalysisNode
from apps.agents.nodes.vuln_research_node import VulnResearchNode
from apps.agents.nodes.exposure_node import ExposureNode
from apps.agents.nodes.investigation_node import InvestigationNode
from apps.agents.nodes.response_node import ResponseNode

logger = logging.getLogger("SecurityGraph")


class SecurityGraph:
    """
    Orchestrates the sequential and conditional execution of security nodes
    over the shared SecurityState contract.
    """

    def __init__(self):
        self.ingestion_node = IngestionNode()
        self.email_analysis_node = EmailAnalysisNode()
        self.vuln_research_node = VulnResearchNode()
        self.exposure_node = ExposureNode()
        self.investigation_node = InvestigationNode()
        self.response_node = ResponseNode()

    def run(self, initial_state: SecurityState) -> SecurityState:
        """
        Executes the security analysis workflow across all nodes.
        """
        state = initial_state
        logger.info(f"--- [WORKFLOW START] Initializing run for tenant '{state.get('tenant_id')}' ---")

        # Step 1: Ingestion & Privacy Boundary
        state = self.ingestion_node.execute(state)
        if state.get("errors"):
            logger.error(f"Ingestion failed: {state['errors']}")
            return state

        # Step 2: Static & Sandbox Email Analysis
        state = self.email_analysis_node.execute(state)

        # Step 3: Vulnerability & Threat Intelligence Research
        state = self.vuln_research_node.execute(state)

        # Step 4: Exposure & Attack Surface Correlation
        state = self.exposure_node.execute(state)

        # Step 5: Investigation, Scoring & Attack Chain Reconstruction
        state = self.investigation_node.execute(state)

        # Step 6: Response Planning & Policy Gating
        state = self.response_node.execute(state)

        logger.info(f"--- [WORKFLOW COMPLETE] Incident created with confidence {state.get('confidence')} ---")
        return state
