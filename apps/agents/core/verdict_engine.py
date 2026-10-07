"""
VerdictEngine: the single source of truth for an email's risk verdict.

The verdict is computed exclusively from typed Evidence records in the InvestigationState.
Every point of risk is attributed to a concrete evidence ID; nothing is added for an
indicator that was not observed. Absent data stays absent (e.g. missing authentication
results are reported as UNKNOWN, never as a pass).
"""

from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from apps.agents.core.investigation_state import Evidence, InvestigationState


class VerdictFactor(BaseModel):
    component: str
    delta: float
    reason: str
    evidence_id: str


class EmailVerdict(BaseModel):
    verdict: str = "BENIGN"  # BENIGN, SUSPICIOUS, MALICIOUS
    severity: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score: float = 0.0
    confidence: float = 0.5
    factors: List[VerdictFactor] = Field(default_factory=list)
    title: str = "No malicious indicators observed"
    threat_category: str = "No Threat Observed"
    interaction_required: str = "NONE"
    cve: Optional[str] = None
    cve_in_kev: bool = False
    forced_authentication: bool = False


# (evidence_type, component label, delta, reason template). Each type is counted at most once.
_WEIGHTS: Dict[str, tuple] = {
    "MONIKER_URI": ("Forced-authentication / moniker URI", 45.0, "Message contains a non-network URI scheme that can trigger client-side NTLM leakage or rendering exploitation"),
    "UNC_PATH": ("UNC path reference", 45.0, "Message references a remote UNC/SMB path that can force outbound authentication"),
    "DECEPTIVE_LINK": ("Deceptive link", 25.0, "Displayed link text points to a different destination than the actual href"),
    "UNICODE_ANOMALY": ("Unicode obfuscation", 20.0, "Bidirectional-override, zero-width, tag or confusable characters detected"),
    "ACTIVE_SCRIPT": ("Active scripting", 20.0, "Script content embedded in the message body"),
    "DATA_URI": ("Inline data URI payload", 10.0, "Inline data: URI payload embedded in the message body"),
}

SEVERITY_THRESHOLDS = [(70.0, "CRITICAL"), (45.0, "HIGH"), (20.0, "MEDIUM")]
VERDICT_THRESHOLDS = [(45.0, "MALICIOUS"), (20.0, "SUSPICIOUS")]


def _first(state: InvestigationState, evidence_type: str) -> Optional[Evidence]:
    for ev in state.evidence.values():
        if ev.evidence_type == evidence_type:
            return ev
    return None


def _all(state: InvestigationState, evidence_type: str) -> List[Evidence]:
    return [ev for ev in state.evidence.values() if ev.evidence_type == evidence_type]


def severity_for(score: float) -> str:
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"


def verdict_for(score: float) -> str:
    for threshold, label in VERDICT_THRESHOLDS:
        if score >= threshold:
            return label
    return "BENIGN"


def compute_verdict(state: InvestigationState) -> EmailVerdict:
    factors: List[VerdictFactor] = []

    def add(component: str, delta: float, reason: str, ev: Evidence):
        factors.append(VerdictFactor(component=component, delta=round(delta, 1), reason=reason, evidence_id=ev.id))

    auth = _first(state, "AUTHENTICATION")
    if auth and auth.metadata.get("result") == "FAIL":
        add("Sender authentication failure", 25.0, f"Authentication-Results reported failure ({auth.value})", auth)

    for ev_type, (component, delta, reason) in _WEIGHTS.items():
        ev = _first(state, ev_type)
        if ev:
            add(component, delta, reason, ev)

    attachments = _all(state, "ATTACHMENT_ANALYSIS")
    if attachments:
        worst = max(attachments, key=lambda e: float(e.metadata.get("risk_score", 0.0) or 0.0))
        att_risk = float(worst.metadata.get("risk_score", 0.0) or 0.0)
        if att_risk > 0:
            add("Attachment risk", att_risk * 0.6, f"Static attachment analysis scored {att_risk:.0f}/100 ({worst.subject or 'attachment'})", worst)
    motw = _first(state, "ATTACHMENT_PE")
    if motw:
        add("Mark-of-the-Web evasion container", 15.0, "Container format that strips Mark-of-the-Web around an executable payload", motw)

    for rep in _all(state, "URL_REPUTATION"):
        if rep.metadata.get("is_malicious") is True:
            add("Threat-intel reputation", 45.0, f"Reputation feed flagged {rep.subject} as malicious", rep)
            break

    sandbox_scores = {"MALICIOUS": 35.0, "BLOCKED_SSRF": 20.0, "SUSPICIOUS": 15.0}
    best_sb = None
    for sb in _all(state, "BEHAVIORAL_SANDBOX"):
        v = str(sb.metadata.get("verdict", "")).upper()
        if v in sandbox_scores and (best_sb is None or sandbox_scores[v] > sandbox_scores[best_sb[0]]):
            best_sb = (v, sb)
    if best_sb:
        v, sb = best_sb
        reason = "URL analysis verdict " + v + (" (link targets a private/internal network destination)" if v == "BLOCKED_SSRF" else "")
        add("Link analysis", sandbox_scores[v], reason, sb)

    cve = None
    cve_in_kev = False
    kev = _first(state, "CISA_KEV_MATCH")
    if kev:
        cve = kev.metadata.get("cve_id")
        cve_in_kev = bool(kev.metadata.get("is_in_kev"))
        if cve_in_kev:
            add("Known exploited vulnerability", 10.0, f"{cve} is listed in the CISA KEV catalog", kev)
    elif _first(state, "CVE_CANDIDATE"):
        cve = _first(state, "CVE_CANDIDATE").metadata.get("cve_id")

    score = round(min(100.0, sum(f.delta for f in factors)), 1)
    severity = severity_for(score)
    verdict = verdict_for(score)

    forced_auth = bool(_first(state, "MONIKER_URI") or _first(state, "UNC_PATH"))
    if forced_auth:
        title = "Forced-authentication / moniker link exploitation attempt"
        category = "Forced Authentication (Moniker/UNC)"
        interaction = "VIEW"
    elif any(f.component == "Threat-intel reputation" for f in factors):
        title = "Link to known-malicious infrastructure"
        category = "Malicious URL"
        interaction = "CLICK"
    elif _first(state, "DECEPTIVE_LINK"):
        title = "Deceptive phishing link"
        category = "Credential Phishing"
        interaction = "CLICK"
    elif any(f.component.startswith("Attachment") or f.component.startswith("Mark-of") for f in factors):
        title = "High-risk attachment"
        category = "Malicious Attachment"
        interaction = "OPEN_ATTACHMENT"
    elif _first(state, "UNICODE_ANOMALY"):
        title = "Unicode obfuscation in message"
        category = "Obfuscation / Evasion"
        interaction = "VIEW"
    elif auth and auth.metadata.get("result") == "FAIL":
        title = "Unauthenticated sender (SPF/DMARC failure)"
        category = "Sender Spoofing"
        interaction = "NONE"
    else:
        title = "No malicious indicators observed"
        category = "No Threat Observed"
        interaction = "NONE"
    if cve:
        title = f"{title} ({cve})"

    # Confidence grows with the number of independent supporting factors and with resolved questions.
    resolved = sum(1 for q in state.questions.values() if q.status == "RESOLVED")
    total_q = max(1, len(state.questions))
    confidence = round(min(0.95, 0.5 + 0.1 * len(factors) + 0.2 * (resolved / total_q)), 2)

    return EmailVerdict(
        verdict=verdict,
        severity=severity,
        risk_score=score,
        confidence=confidence,
        factors=factors,
        title=title,
        threat_category=category,
        interaction_required=interaction,
        cve=cve,
        cve_in_kev=cve_in_kev,
        forced_authentication=forced_auth,
    )
