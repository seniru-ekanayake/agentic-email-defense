"""
Normalized Threat Intelligence Models with strict provenance and confidence tracking.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
import datetime
from pydantic import BaseModel, Field

from packages.schemas.python.models import EmailExploitabilityAssessment, InteractionRequirement


class ThreatIntelSource(str, Enum):
    NVD = "NVD"
    CISA_KEV = "CISA_KEV"
    MITRE_ATTACK = "MITRE_ATTACK"
    GITHUB_ADVISORY = "GITHUB_ADVISORY"
    VENDOR_ADVISORY = "VENDOR_ADVISORY"


class Provenance(BaseModel):
    source: ThreatIntelSource
    source_url: str
    retrieved_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    published_at: Optional[str] = None
    modified_at: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    raw_hash: Optional[str] = None


class KevRecord(BaseModel):
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    known_ransomware_use: str
    notes: Optional[str] = None
    provenance: Provenance


class CveRecord(BaseModel):
    cve_id: str
    description: str
    cvss_v3_score: Optional[float] = None
    cvss_v3_vector: Optional[str] = None
    attack_vector: Optional[str] = None  # NETWORK, ADJACENT, LOCAL, PHYSICAL
    user_interaction: Optional[str] = None  # NONE, REQUIRED
    attack_complexity: Optional[str] = None  # LOW, HIGH
    privileges_required: Optional[str] = None  # NONE, LOW, HIGH
    cpe_match: List[str] = Field(default_factory=list)
    cwe_ids: List[str] = Field(default_factory=list)
    is_in_kev: bool = False
    epss_score: Optional[float] = None
    references: List[str] = Field(default_factory=list)
    provenance: Provenance


class MitreTechnique(BaseModel):
    technique_id: str  # e.g., T1566.001
    name: str
    tactic: str  # e.g., Initial Access, Execution
    description: str
    platforms: List[str] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)
    detection_guidance: Optional[str] = None
    provenance: Provenance
