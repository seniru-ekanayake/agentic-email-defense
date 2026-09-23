"""
AttackSurfaceScoringEngine: Explainable, evidence-backed multi-dimensional risk scoring.
Deterministic mathematical formulation — never collapses into an unexplained AI number.
"""

from typing import Dict, Any, List, Optional
from packages.schemas.python.models import InteractionRequirement, EmailAttackRepresentation, EmailExploitabilityAssessment
from packages.attack_surface.src.models import EmailAsset, AssetState, AttackSurfaceScores


class AttackSurfaceScoringEngine:
    """
    Computes distinct, evidence-backed scores for email attack surface and active incidents.
    """

    INTERACTION_WEIGHTS = {
        InteractionRequirement.NONE: 100.0,
        InteractionRequirement.VIEW: 90.0,
        InteractionRequirement.HOVER: 70.0,
        InteractionRequirement.CLICK: 50.0,
        InteractionRequirement.OPEN_ATTACHMENT: 40.0,
        InteractionRequirement.EXECUTE_ATTACHMENT: 30.0,
        InteractionRequirement.MULTI_STEP: 20.0,
    }

    def score(
        self,
        asset: EmailAsset,
        assessment: Optional[EmailExploitabilityAssessment] = None,
        email_rep: Optional[EmailAttackRepresentation] = None,
        observed_auth_anomaly: bool = False
    ) -> AttackSurfaceScores:
        evidence: List[Dict[str, Any]] = []

        # 1. Exposure Score (0-100)
        exposure_score = 0.0
        if asset.is_internet_facing:
            exposure_score += 50.0
            evidence.append({"factor": "Internet Exposure", "impact": 50.0, "reasoning": f"Asset {asset.host} is directly reachable from the public internet."})
        if asset.webmail_path:
            exposure_score += 30.0
            evidence.append({"factor": "Public Webmail Endpoint", "impact": 30.0, "reasoning": f"Webmail portal exposed at {asset.webmail_path}."})
        if asset.version:
            exposure_score += 20.0
            evidence.append({"factor": "Version Disclosed", "impact": 20.0, "reasoning": f"Software version {asset.version} discovered via public banners/headers."})
        exposure_score = min(exposure_score, 100.0)

        # 2. Exploitability Score (0-100)
        exploitability_score = 0.0
        if assessment:
            if assessment.cve:
                exploitability_score += 40.0
                evidence.append({"factor": "Known CVE Assigned", "impact": 40.0, "reasoning": f"Associated with vulnerability {assessment.cve}."})
            if AssetState.KNOWN_EXPLOITABLE in asset.states:
                exploitability_score += 40.0
                evidence.append({"factor": "CISA KEV Catalogued", "impact": 40.0, "reasoning": "Vulnerability is actively exploited in the wild (CISA KEV)."})
            if not assessment.authentication_required:
                exploitability_score += 20.0
                evidence.append({"factor": "Unauthenticated Exploitation", "impact": 20.0, "reasoning": "Attack requires no prior authentication."})
        exploitability_score = min(exploitability_score, 100.0)

        # 3. Email Delivery Score (0-100)
        email_delivery_score = 0.0
        if assessment and assessment.email_delivery_possible:
            email_delivery_score = 90.0
            evidence.append({"factor": "Email Deliverable Vector", "impact": 90.0, "reasoning": "Vulnerability can be triggered directly via inbound email/MIME payload."})
        elif email_rep:
            email_delivery_score = 70.0
            evidence.append({"factor": "Inbound Message Received", "impact": 70.0, "reasoning": "Email payload reached mailbox infrastructure."})

        # 4. Interaction Requirement Score (0-100)
        # Low interaction required (VIEW or NONE) yields the highest risk score
        interaction_score = 30.0  # default moderate
        if assessment:
            interaction_score = self.INTERACTION_WEIGHTS.get(assessment.interaction_required, 50.0)
            evidence.append({
                "factor": f"Interaction Requirement: {assessment.interaction_required.value}",
                "impact": interaction_score,
                "reasoning": f"Victim requires '{assessment.interaction_required.value}' interaction to trigger exploitation."
            })

        # 5. Identity Impact Score (0-100)
        identity_impact_score = 30.0
        if email_rep:
            if any(t.is_vip for t in email_rep.identity_targets):
                identity_impact_score += 40.0
                evidence.append({"factor": "VIP / Executive Target", "impact": 40.0, "reasoning": "Targeted recipient is an executive or high-privilege account."})
            if assessment and "NTLM" in assessment.session_impact:
                identity_impact_score += 30.0
                evidence.append({"factor": "Credential / Hash Harvesting", "impact": 30.0, "reasoning": "Exploit forces NTLM authentication leak."})
        identity_impact_score = min(identity_impact_score, 100.0)

        # 6. Observed Attack Score (0-100)
        observed_attack_score = 0.0
        if email_rep and email_rep.exploit_indicators:
            observed_attack_score = 95.0
            evidence.append({"factor": "Active Exploit Pattern Observed", "impact": 95.0, "reasoning": f"Observed {len(email_rep.exploit_indicators)} exploit indicator(s) in parsed message."})
        elif AssetState.ATTACK_OBSERVED in asset.states:
            observed_attack_score = 80.0

        # 7. Compromise Confidence (0.0 - 1.0)
        confidence = 0.50
        if observed_attack_score > 80:
            confidence += 0.30
        if observed_auth_anomaly:
            confidence += 0.15
            evidence.append({"factor": "Post-Delivery Auth Anomaly", "impact": 15.0, "reasoning": "Correlated authentication or session activity observed after delivery."})
        if assessment and assessment.confidence:
            confidence = (confidence + assessment.confidence) / 2.0
        confidence = min(round(confidence, 2), 0.99)

        # 8. Business Impact (0-100)
        business_impact = 50.0
        if any(t.is_vip for t in (email_rep.identity_targets if email_rep else [])):
            business_impact += 30.0
        if "RCE" in (assessment.session_impact if assessment else ""):
            business_impact += 20.0
        business_impact = min(business_impact, 100.0)

        # Overall Risk Score (Weighted Formula)
        overall_risk_score = (
            (exposure_score * 0.15) +
            (exploitability_score * 0.20) +
            (email_delivery_score * 0.15) +
            (interaction_score * 0.20) +
            (identity_impact_score * 0.15) +
            (observed_attack_score * 0.15)
        )
        overall_risk_score = round(min(overall_risk_score, 100.0), 1)

        # Severity mapping
        if overall_risk_score >= 80.0:
            severity = "CRITICAL"
        elif overall_risk_score >= 60.0:
            severity = "HIGH"
        elif overall_risk_score >= 40.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return AttackSurfaceScores(
            exposure_score=exposure_score,
            exploitability_score=exploitability_score,
            email_delivery_score=email_delivery_score,
            interaction_score=interaction_score,
            identity_impact_score=identity_impact_score,
            observed_attack_score=observed_attack_score,
            compromise_confidence=confidence,
            business_impact=business_impact,
            overall_risk_score=overall_risk_score,
            severity=severity,
            evidence=evidence
        )
