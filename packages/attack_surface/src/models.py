"""
Canonical Data Models for Email Attack Surface Discovery and Multi-Dimensional Scoring.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
import datetime
from pydantic import BaseModel, Field

from packages.schemas.python.models import InteractionRequirement


class AssetState(str, Enum):
    ASSET_DISCOVERED = "ASSET_DISCOVERED"
    ASSET_EXPOSED = "ASSET_EXPOSED"
    SOFTWARE_IDENTIFIED = "SOFTWARE_IDENTIFIED"
    VERSION_IDENTIFIED = "VERSION_IDENTIFIED"
    VULNERABLE = "VULNERABLE"
    KNOWN_EXPLOITABLE = "KNOWN_EXPLOITABLE"
    EMAIL_DELIVERABLE_EXPLOIT_POSSIBLE = "EMAIL_DELIVERABLE_EXPLOIT_POSSIBLE"
    ATTACK_OBSERVED = "ATTACK_OBSERVED"
    COMPROMISE_SUSPECTED = "COMPROMISE_SUSPECTED"
    COMPROMISE_CONFIRMED = "COMPROMISE_CONFIRMED"


class DnsDiscoveryResult(BaseModel):
    domain: str
    mx_records: List[str] = Field(default_factory=list)
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    mail_hosts: List[str] = Field(default_factory=list)
    discovered_ips: List[str] = Field(default_factory=list)


class EmailAsset(BaseModel):
    asset_id: str
    tenant_id: str
    domain: str
    host: str
    ip_address: Optional[str] = None
    port: int = 443
    service_type: str = "HTTPS/Webmail"  # SMTP, IMAP, HTTPS/Webmail, OWA, ZimbraWebClient
    webmail_path: Optional[str] = None  # e.g., /owa, /zimbra, /roundcube
    product: Optional[str] = None  # Microsoft Exchange / OWA, Zimbra, Google Workspace, Roundcube
    version: Optional[str] = None  # e.g., 15.2.1118.7
    is_internet_facing: bool = True
    states: List[AssetState] = Field(default_factory=lambda: [AssetState.ASSET_DISCOVERED])
    associated_cves: List[str] = Field(default_factory=list)
    mitigations_present: List[str] = Field(default_factory=list)
    discovered_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    last_scanned_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class AttackSurfaceScores(BaseModel):
    exposure_score: float = Field(ge=0.0, le=100.0)
    exploitability_score: float = Field(ge=0.0, le=100.0)
    email_delivery_score: float = Field(ge=0.0, le=100.0)
    interaction_score: float = Field(ge=0.0, le=100.0)  # High score for VIEW/NONE interaction (most dangerous)
    identity_impact_score: float = Field(ge=0.0, le=100.0)
    observed_attack_score: float = Field(ge=0.0, le=100.0)
    compromise_confidence: float = Field(ge=0.0, le=1.0)
    business_impact: float = Field(ge=0.0, le=100.0)
    overall_risk_score: float = Field(ge=0.0, le=100.0)
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
