"""
Canonical Ontology and Models for the Security Attack Graph.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
import datetime
from pydantic import BaseModel, Field


class GraphEntityType(str, Enum):
    THREAT_ACTOR = "ThreatActor"
    CAMPAIGN = "Campaign"
    EMAIL = "Email"
    URL = "URL"
    ATTACHMENT = "Attachment"
    CVE = "CVE"
    SOFTWARE = "Software"
    ASSET = "Asset"
    IDENTITY = "Identity"
    SESSION = "Session"
    INCIDENT = "Incident"
    RESPONSE = "Response"


class GraphRelationType(str, Enum):
    ORCHESTRATES = "ORCHESTRATES"
    SENDS = "SENDS"
    CONTAINS = "CONTAINS"
    EXPLOITS = "EXPLOITS"
    TARGETS = "TARGETS"
    AFFECTS = "AFFECTS"
    OWNS = "OWNS"
    ACCESSES = "ACCESSES"
    INDICATES = "INDICATES"
    TRIGGERS = "TRIGGERS"
    DELIVERS = "DELIVERS"


class GraphNode(BaseModel):
    id: str
    label: str  # e.g., Email, Identity, CVE
    name: str
    properties: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str
    properties: Dict[str, Any] = Field(default_factory=dict)


class AttackGraphData(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)


class AttackPath(BaseModel):
    path_id: str
    start_entity: str
    target_entity: str
    length: int
    steps: List[str]
    description: str
