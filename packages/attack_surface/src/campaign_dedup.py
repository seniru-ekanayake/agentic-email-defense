"""Real-Time Campaign Incident Deduplication & Rollup Engine.

Collapses high-volume, concurrent email attack waves (e.g. 1,000 Moniker exploit
or BEC lures) into a single cohesive Campaign Incident entity with aggregate metrics,
completely eliminating SOC alert fatigue.
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from packages.schemas.python.models import EmailAttackRepresentation


class CampaignCluster(BaseModel):
    """Represents an aggregated enterprise campaign clustering multiple related emails."""

    campaign_id: str
    fingerprint: str
    first_seen: float
    last_seen: float
    total_email_count: int = 1
    recipients_targeted: List[str] = Field(default_factory=list)
    unique_recipient_domains: List[str] = Field(default_factory=list)
    target_cve: Optional[str] = None
    sender_domains: List[str] = Field(default_factory=list)
    highest_risk_score: float = 0.0
    highest_severity: str = "LOW"
    sample_message_ids: List[str] = Field(default_factory=list)
    attack_techniques: List[str] = Field(default_factory=list)
    is_active: bool = True


class CampaignFingerprinter:
    """Computes robust attack vector fingerprints for incoming emails."""

    @staticmethod
    def normalize_subject(subject: str) -> str:
        """Strip dynamic timestamps, ticket IDs, and randomized digits from subject."""
        if not subject:
            return "empty_subject"
        s = subject.lower().strip()
        s = re.sub(r"\[ticket[#-]?\d+\]", "[ticket]", s)
        s = re.sub(r"\b\d{4,}\b", "0000", s)
        s = re.sub(r"\s+", " ", s)
        return s

    @staticmethod
    def extract_uri_pattern(urls: List[Any]) -> str:
        """Extract canonical URI schemes and target hosts."""
        if not urls:
            return "no_urls"
        patterns = []
        for u in sorted(urls, key=lambda x: getattr(x, "url", "")):
            url_str = getattr(u, "url", "")
            if url_str.startswith("search-ms:"):
                patterns.append("search-ms-moniker")
            elif url_str.startswith("file://"):
                patterns.append("file-unc-moniker")
            elif "oauth" in url_str.lower():
                patterns.append("oauth-consent-lure")
            else:
                domain = getattr(u, "domain", "unknown")
                patterns.append(f"http:{domain}")
        return "|".join(patterns[:3])

    @classmethod
    def compute_fingerprint(cls, ear: EmailAttackRepresentation) -> str:
        """Generate deterministic 64-char SHA256 attack vector signature."""
        sender_domain = ear.sender.domain.lower() if ear.sender and ear.sender.domain else "unknown"
        norm_subject = cls.normalize_subject(ear.headers.get("Subject", ear.headers.get("subject", "")))
        uri_pattern = cls.extract_uri_pattern(ear.urls)
        
        cve = "no_cve"
        for ind in ear.exploit_indicators:
            if ind.target_cve:
                cve = ind.target_cve.upper()
                break

        auth_status = f"spf:{ear.authentication.spf}|dkim:{ear.authentication.dkim}" if ear.authentication else "no_auth"

        raw_sig = f"{sender_domain}::{cve}::{uri_pattern}::{norm_subject}::{auth_status}"
        return hashlib.sha256(raw_sig.encode("utf-8")).hexdigest()


class CampaignAggregator:
    """Stateful aggregator that maintains active campaign clusters and rolls up incidents."""

    _instance: Optional[CampaignAggregator] = None

    def __init__(self, time_window_seconds: float = 86400.0):
        self.time_window = time_window_seconds
        self.campaigns: Dict[str, CampaignCluster] = {}  # fingerprint -> CampaignCluster
        self._id_to_fp: Dict[str, str] = {}              # campaign_id -> fingerprint

    @classmethod
    def get_instance(cls) -> CampaignAggregator:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def register_email(
        self,
        ear: EmailAttackRepresentation,
        risk_score: float = 0.0,
        severity: str = "MEDIUM",
        timestamp: Optional[float] = None
    ) -> Tuple[CampaignCluster, bool]:
        """Register an email. Returns (CampaignCluster, is_new_campaign)."""
        now = timestamp or time.time()
        fp = CampaignFingerprinter.compute_fingerprint(ear)

        recipient_emails = [r.address.lower() for r in ear.recipients if r.address]
        recipient_domains = list(set([r.split("@")[1] for r in recipient_emails if "@" in r]))
        sender_domain = ear.sender.domain.lower() if ear.sender and ear.sender.domain else "unknown"

        cve = None
        for ind in ear.exploit_indicators:
            if ind.target_cve:
                cve = ind.target_cve.upper()
                break

        # Check if active campaign cluster exists within the time window
        if fp in self.campaigns:
            camp = self.campaigns[fp]
            if (now - camp.last_seen) <= self.time_window:
                # Update existing campaign
                camp.last_seen = now
                camp.total_email_count += 1
                for r in recipient_emails:
                    if r not in camp.recipients_targeted:
                        camp.recipients_targeted.append(r)
                for d in recipient_domains:
                    if d not in camp.unique_recipient_domains:
                        camp.unique_recipient_domains.append(d)
                if sender_domain not in camp.sender_domains:
                    camp.sender_domains.append(sender_domain)
                if risk_score > camp.highest_risk_score:
                    camp.highest_risk_score = risk_score
                    camp.highest_severity = severity
                if ear.message_id not in camp.sample_message_ids and len(camp.sample_message_ids) < 10:
                    camp.sample_message_ids.append(ear.message_id)

                return camp, False

        # Create new campaign
        camp_id = f"CAMP-{fp[:8].upper()}"
        new_camp = CampaignCluster(
            campaign_id=camp_id,
            fingerprint=fp,
            first_seen=now,
            last_seen=now,
            total_email_count=1,
            recipients_targeted=recipient_emails,
            unique_recipient_domains=recipient_domains,
            target_cve=cve,
            sender_domains=[sender_domain],
            highest_risk_score=risk_score,
            highest_severity=severity,
            sample_message_ids=[ear.message_id],
            is_active=True
        )

        self.campaigns[fp] = new_camp
        self._id_to_fp[camp_id] = fp
        return new_camp, True

    def get_campaign_by_id(self, campaign_id: str) -> Optional[CampaignCluster]:
        fp = self._id_to_fp.get(campaign_id)
        return self.campaigns.get(fp) if fp else None

    def list_active_campaigns(self) -> List[CampaignCluster]:
        return [c for c in self.campaigns.values() if c.is_active]

    def clear(self) -> None:
        self.campaigns.clear()
        self._id_to_fp.clear()
