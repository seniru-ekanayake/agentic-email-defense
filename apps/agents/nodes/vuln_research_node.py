"""
Agent Node 3: Vulnerability Research Node.
Determines vulnerability impact, email delivery feasibility, and interaction requirements.
Combines deterministic threat intel with LLMGateway structured reasoning.
"""

import json
import logging
from typing import Dict, Any, List, Optional

from packages.schemas.python.models import SecurityState, EmailExploitabilityAssessment, InteractionRequirement
from packages.threat_intel.src.nvd import NvdIngestor
from packages.threat_intel.src.cisa_kev import CisaKevIngestor
from packages.threat_intel.src.exploitability_analyzer import EmailExploitabilityAnalyzer
from apps.agents.core.llm_gateway import LLMGateway

logger = logging.getLogger("VulnResearchNode")


class VulnResearchNode:
    def __init__(self, llm_gateway: Optional[LLMGateway] = None):
        self.nvd = NvdIngestor()
        self.kev_ingestor = CisaKevIngestor()
        self.analyzer = EmailExploitabilityAnalyzer()
        self.gateway = llm_gateway or LLMGateway()
        self.kev_map = {r.cve_id: r for r in self.kev_ingestor.ingest(live=False)}

    def execute(self, state: SecurityState) -> SecurityState:
        logger.info("VulnResearchNode executing...")
        
        # 1. Identify CVEs in evidence or exploit indicators
        cves_to_research = set()
        for ev in state.get("evidence", []):
            if ev.get("cve"):
                cves_to_research.add(ev["cve"])

        assessments: List[Dict[str, Any]] = []

        for cve_id in cves_to_research:
            cve_rec = self.nvd.fetch_cve(cve_id, live=False)
            kev_rec = self.kev_map.get(cve_id)
            
            if cve_rec:
                # Deterministic baseline assessment
                base_assessment = self.analyzer.assess_cve(cve_rec, kev_rec)
                
                # Check data privacy boundary before LLM call
                is_confidential = state.get("data_classification") in ["CONFIDENTIAL", "RESTRICTED"]
                provider = self.gateway.get_provider(is_confidential=is_confidential)
                
                system_prompt = (
                    "You are a Principal Vulnerability Research Agent. Analyze the provided CVE data and verify "
                    "whether email rendering triggers low-interaction exploitation. Return structured JSON matching EmailExploitabilityAssessment."
                )
                user_prompt = f"Vulnerability: {cve_id}\nDescription: {cve_rec.description}\nKnown in KEV: {kev_rec is not None}"

                try:
                    llm_resp = provider.generate(
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        response_schema={"type": "object"}
                    )
                    # Merge deterministic assessment with verified model output
                    merged_dict = base_assessment.model_dump()
                    if llm_resp.structured_json and "interaction_required" in llm_resp.structured_json:
                        merged_dict["interaction_required"] = llm_resp.structured_json["interaction_required"]
                    assessments.append(merged_dict)
                except Exception as e:
                    logger.warning(f"LLM reasoning fallback to deterministic assessment: {e}")
                    assessments.append(base_assessment.model_dump())

        state["vulnerability_context"] = assessments
        
        # Add hypotheses based on research
        for ass in assessments:
            state.setdefault("hypotheses", []).append({
                "hypothesis": f"Attacker is exploiting {ass['cve']} on target webmail/rendering engine.",
                "interaction_required": ass["interaction_required"],
                "session_impact": ass["session_impact"],
                "confidence": ass["confidence"]
            })

        logger.info(f"VulnResearchNode completed. Formulated {len(assessments)} vulnerability assessment(s).")
        return state
