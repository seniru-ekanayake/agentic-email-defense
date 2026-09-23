"""
Canonical Pydantic models and types for the Email Exploitation Detection & Response Platform.
Generated to strictly match packages/schemas/*.json specifications.
"""

from enum import Enum
from typing import List, Dict, Any, Optional, Union
from pydantic import BaseModel, Field
from typing_extensions import TypedDict


class DataClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class InteractionRequirement(str, Enum):
    NONE = "NONE"
    VIEW = "VIEW"
    HOVER = "HOVER"
    CLICK = "CLICK"
    OPEN_ATTACHMENT = "OPEN_ATTACHMENT"
    EXECUTE_ATTACHMENT = "EXECUTE_ATTACHMENT"
    MULTI_STEP = "MULTI_STEP"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ApprovalRequirement(str, Enum):
    AUTOMATIC = "AUTOMATIC"
    POLICY_DEPENDENT = "POLICY_DEPENDENT"
    MANDATORY_HUMAN = "MANDATORY_HUMAN"


# --- Email Attack Representation Sub-models ---

class SenderInfo(BaseModel):
    address: str
    display_name: Optional[str] = None
    domain: Optional[str] = None


class RecipientInfo(BaseModel):
    address: str
    display_name: Optional[str] = None
    type: str = "to"  # to, cc, bcc


class AuthenticationResults(BaseModel):
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
    auth_results_raw: Optional[str] = None


class MimeStructure(BaseModel):
    content_type: Optional[str] = None
    boundary: Optional[str] = None
    structure_depth: int = 1
    is_multipart: bool = False
    parts_summary: List[str] = Field(default_factory=list)
    malformed_indicators: List[str] = Field(default_factory=list)


class HtmlFeatures(BaseModel):
    has_forms: bool = False
    has_scripts: bool = False
    has_iframes: bool = False
    has_svg_xml: bool = False
    has_external_css: bool = False
    has_remote_images: bool = False
    hidden_elements_count: int = 0
    suspicious_tags: List[str] = Field(default_factory=list)


class BodyFeatures(BaseModel):
    text_plain: Optional[str] = None
    text_html: Optional[str] = None
    html_features: Optional[HtmlFeatures] = None


class UrlFeature(BaseModel):
    url: str
    domain: str
    display_text: Optional[str] = None
    is_mismatched: bool = False
    is_ip_based: bool = False
    is_punycode: bool = False
    reputation: Optional[str] = "unknown"


class AttachmentFeature(BaseModel):
    filename: str
    content_type: str
    sha256: str
    size_bytes: int
    magic_type: Optional[str] = None
    is_executable: bool = False
    has_macros: bool = False
    archive_contents: List[str] = Field(default_factory=list)


class ExploitIndicator(BaseModel):
    indicator_type: str
    evidence: str
    target_software: Optional[str] = None
    target_cve: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0)


class IdentityTarget(BaseModel):
    email: str
    user_id: Optional[str] = None
    department: Optional[str] = None
    is_vip: bool = False
    privilege_level: Optional[str] = "standard"


class RiskEvidence(BaseModel):
    factor: str
    score_impact: float
    reasoning: str


class EmailAttackRepresentation(BaseModel):
    message_id: str
    timestamp: str
    sender: SenderInfo
    recipients: List[RecipientInfo] = Field(default_factory=list)
    authentication: AuthenticationResults
    headers: Dict[str, str] = Field(default_factory=dict)
    mime: MimeStructure = Field(default_factory=MimeStructure)
    body: BodyFeatures = Field(default_factory=BodyFeatures)
    urls: List[UrlFeature] = Field(default_factory=list)
    attachments: List[AttachmentFeature] = Field(default_factory=list)
    embedded_content: List[Dict[str, Any]] = Field(default_factory=list)
    rendering_features: List[str] = Field(default_factory=list)
    parser_features: List[str] = Field(default_factory=list)
    behavioral_features: List[str] = Field(default_factory=list)
    exploit_indicators: List[ExploitIndicator] = Field(default_factory=list)
    identity_targets: List[IdentityTarget] = Field(default_factory=list)
    classification: DataClassification = DataClassification.INTERNAL
    risk_evidence: List[RiskEvidence] = Field(default_factory=list)


class EmailExploitabilityAssessment(BaseModel):
    cve: str
    affected_product: str
    affected_component: str
    attack_vector: str
    email_delivery_possible: bool
    rendering_required: bool
    interaction_required: InteractionRequirement
    authentication_required: bool
    session_impact: str
    likely_post_exploitation: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


# --- Tool Registry Schemas ---

class ToolDefinition(BaseModel):
    name: str
    description: str
    risk_level: RiskLevel
    required_permission: str
    approval_requirement: ApprovalRequirement
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]
    audit_required: bool = True


class ToolProposal(BaseModel):
    tool_name: str
    parameters: Dict[str, Any]
    reasoning: str
    confidence: float = 1.0


class ToolExecutionResult(BaseModel):
    tool_name: str
    success: bool
    executed: bool
    requires_human_approval: bool = False
    approval_token: Optional[str] = None
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    audit_id: str


# --- LangGraph SecurityState (TypedDict) ---

class SecurityState(TypedDict, total=False):
    tenant_id: str
    workflow_id: str
    autonomy_level: int  # 0 to 4
    email_representation: Dict[str, Any]
    data_classification: str
    asset_context: List[Dict[str, Any]]
    vulnerability_context: List[Dict[str, Any]]
    sandbox_telemetry: Optional[Dict[str, Any]]
    identity_telemetry: List[Dict[str, Any]]
    graph_context: Dict[str, Any]
    evidence: List[Dict[str, Any]]
    hypotheses: List[Dict[str, Any]]
    scores: Dict[str, float]  # exposure, exploitability, delivery, interaction, etc.
    confidence: float
    proposed_tools: List[Dict[str, Any]]
    executed_tools: List[Dict[str, Any]]
    pending_approvals: List[Dict[str, Any]]
    incident_report: Optional[Dict[str, Any]]
    errors: List[str]
