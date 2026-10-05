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
        
        # 1. Identify candidate CVEs from asset exposure context or verified threat intel evidence
        cves_to_research: List[str] = []
        for asset in state.get("asset_context", []):
            for cve in asset.get("associated_cves", []):
                if cve not in cves_to_research:
                    cves_to_research.append(cve)

        for ev in state.get("evidence", []):
            if ev.get("cve") and ev["cve"] not in cves_to_research:
                cves_to_research.append(ev["cve"])

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
                    merged_dict = base_assessment.model_dump()
                    if llm_resp.actual_call and llm_resp.status == "COMPLETED" and llm_resp.structured_json:
                        if "interaction_required" in llm_resp.structured_json:
                            raw_ir = str(llm_resp.structured_json["interaction_required"]).upper()
                            valid_ir = {"NONE", "VIEW", "HOVER", "CLICK", "OPEN_ATTACHMENT", "EXECUTE_ATTACHMENT", "MULTI_STEP"}
                            if raw_ir in valid_ir:
                                merged_dict["interaction_required"] = raw_ir
                            elif "PREVIEW" in raw_ir or "READ" in raw_ir:
                                merged_dict["interaction_required"] = "VIEW"
                        merged_dict["assessment_engine"] = "HYBRID"
                    else:
                        merged_dict["assessment_engine"] = "RULE_ENGINE"
                    assessments.append(merged_dict)
                except Exception as e:
                    logger.warning(f"LLM call failed, using deterministic assessment: {e}")
                    fallback_dict = base_assessment.model_dump()
                    fallback_dict["assessment_engine"] = "RULE_ENGINE"
                    assessments.append(fallback_dict)

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
