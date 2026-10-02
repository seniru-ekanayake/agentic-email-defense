"""
Zero-Code Agent Builder, Detection Rules, and Investigation Workflow Engine.
Provides complete visual configuration storage and execution translation for security analysts
without writing code or editing configuration files.
"""

import uuid
import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class ResponsePermission(str, Enum):
    READ_ONLY = "READ_ONLY"
    INVESTIGATE = "INVESTIGATE"
    RECOMMEND = "RECOMMEND"
    AUTHORIZED_RESPONSE = "AUTHORIZED_RESPONSE"


class AgentConfig(BaseModel):
    agent_id: str = Field(default_factory=lambda: f"agent-{uuid.uuid4().hex[:6]}")
    name: str = "Email Security Investigator v1.2"
    description: str = "Autonomous triage of zero-click exploits, moniker links, and BEC."
    purpose: str = "Zero-code perimeter inspection and rapid containment."
    enabled_tools: List[str] = Field(default_factory=lambda: [
        "MimeParser", "UnicodeAnalyzer", "MonikerLinkDetector",
        "UrlReputation", "Quad9DoH", "CisaKevLookup", "NvdCveLookup",
        "SandboxDetonation", "CampaignCluster"
    ])
    investigation_depth: str = "DEEP"  # SHALLOW, STANDARD, DEEP, FORENSIC
    max_execution_time_seconds: int = 120
    max_tool_calls: int = 25
    risk_threshold: float = 65.0
    escalation_threshold: float = 85.0
    evidence_requirements: List[str] = Field(default_factory=lambda: [
        "SPF/DMARC status", "Unicode Tag verification", "DNS resolve status"
    ])
    response_permission: ResponsePermission = ResponsePermission.RECOMMEND
    planner_mode: str = "HYBRID"  # RULE, LLM, HYBRID, AUTO
    hybrid_arbitration_policy: str = "RULE_FIRST"  # RULE_FIRST, CONSENSUS_REQUIRED, EVIDENCE_WEIGHTED, INFORMATION_GAIN_WEIGHTED, SAFETY_FIRST
    max_llm_calls: int = 10
    max_llm_tokens: int = 8000
    max_replanning_cycles: int = 5
    tier_thresholds: Dict[str, float] = Field(default_factory=lambda: {"tier1_rule_max_risk": 30.0, "tier3_llm_min_risk": 70.0})
    active: bool = True
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class DetectionRule(BaseModel):
    rule_id: str = Field(default_factory=lambda: f"rule-{uuid.uuid4().hex[:6]}")
    name: str
    description: str
    enabled: bool = True
    # Visual Logic: WHEN condition AND condition THEN actions
    when_field: str      # e.g. "unicode_tags_detected", "moniker_link_present", "spf_dmarc_failed"
    when_operator: str   # "EQUALS", "CONTAINS", "GREATER_THAN", "EXISTS"
    when_value: str
    and_conditions: List[Dict[str, str]] = Field(default_factory=list)
    then_actions: List[Dict[str, Any]] = Field(default_factory=list)
    risk_score_delta: float = 0.0
    confidence: float = 0.90


class WorkflowNode(BaseModel):
    node_id: str
    node_type: str  # EmailInput, HeaderAnalysis, URLAnalysis, DomainIntel, DNS, AttachmentAnalysis, UnicodeAnalysis, Sandbox, ThreatIntel, LLMAnalysis, EvidenceAggregation, RiskScoring, HumanApproval, Response, Notification
    label: str
    position_x: int = 0
    position_y: int = 0
    config: Dict[str, Any] = Field(default_factory=dict)


class WorkflowEdge(BaseModel):
    edge_id: str
    source_node: str
    target_node: str
    condition: Optional[str] = None


class InvestigationWorkflow(BaseModel):
    workflow_id: str = Field(default_factory=lambda: f"wf-{uuid.uuid4().hex[:6]}")
    name: str = "Standard Enterprise Email Triage Pipeline"
    description: str = "6-stage autonomous investigation with policy-gated containment."
    nodes: List[WorkflowNode] = Field(default_factory=list)
    edges: List[WorkflowEdge] = Field(default_factory=list)
    active: bool = True


class ZeroCodeStore:
    """Manages visual agent configs, visual detection rules, and investigation workflows."""
    _instance: Optional["ZeroCodeStore"] = None

    def __init__(self):
        self._agents: Dict[str, AgentConfig] = {}
        self._rules: Dict[str, DetectionRule] = {}
        self._workflows: Dict[str, InvestigationWorkflow] = {}
        self._seed_default_configs()

    @classmethod
    def get_instance(cls) -> "ZeroCodeStore":
        if cls._instance is None:
            cls._instance = ZeroCodeStore()
        return cls._instance

    def _seed_default_configs(self):
        # Default Primary Agent
        default_agent = AgentConfig(
            agent_id="agent-primary-soc",
            name="Tier-1 Autonomous Email Investigator",
            description="Perimeter investigation agent for high-impact CVEs, Unicode evasion, and malicious callouts.",
            purpose="Autonomous zero-click triage with Level 1 human containment authorization.",
            response_permission=ResponsePermission.RECOMMEND
        )
        self._agents[default_agent.agent_id] = default_agent

        # Default Detection Rules
        r1 = DetectionRule(
            rule_id="rule-unicode-tag-url",
            name="Unicode Tags + URL Evasion Rule",
            description="Triggers deep investigation when Unicode Tag characters or RTLO are detected with external URL.",
            when_field="unicode_anomaly",
            when_operator="EXISTS",
            when_value="true",
            and_conditions=[
                {"field": "has_urls", "operator": "EQUALS", "value": "true"}
            ],
            then_actions=[
                {"action": "increase_risk", "amount": 25},
                {"action": "investigate_url", "tool": "UrlReputation"},
                {"action": "create_evidence", "description": "Unicode obfuscation paired with external hyperlink detected"}
            ],
            risk_score_delta=25.0
        )
        r2 = DetectionRule(
            rule_id="rule-moniker-cve21413",
            name="Outlook Moniker Link Exploit (CVE-2024-21413)",
            description="Detects search-ms / file: links bypassing Outlook security notices.",
            when_field="moniker_exploit",
            when_operator="EXISTS",
            when_value="true",
            and_conditions=[],
            then_actions=[
                {"action": "increase_risk", "amount": 40},
                {"action": "correlate_cve", "cve": "CVE-2024-21413"},
                {"action": "propose_containment", "tool": "quarantine_email"}
            ],
            risk_score_delta=40.0
        )
        self._rules[r1.rule_id] = r1
        self._rules[r2.rule_id] = r2

        # Default Visual Workflow
        default_wf = InvestigationWorkflow(
            workflow_id="wf-default-pipeline",
            name="Production 6-Node Autonomous SOC Pipeline",
            description="Ingestion -> Forensic Parsing -> Threat Intel -> Attack Surface -> Multi-Agent Risk Synthesis -> Safety Gate",
            nodes=[
                WorkflowNode(node_id="n1", node_type="EmailInput", label="Inbound RFC 5322 Ingestion", position_x=50, position_y=150),
                WorkflowNode(node_id="n2", node_type="HeaderAnalysis", label="MIME & Authentication (SPF/DMARC)", position_x=250, position_y=150),
                WorkflowNode(node_id="n3", node_type="UnicodeAnalysis", label="Unicode Anomaly & Homoglyphs", position_x=450, position_y=100),
                WorkflowNode(node_id="n4", node_type="URLAnalysis", label="Hyperlink & Moniker Extraction", position_x=450, position_y=200),
                WorkflowNode(node_id="n5", node_type="ThreatIntel", label="CISA KEV / NVD / Quad9 Intel", position_x=650, position_y=150),
                WorkflowNode(node_id="n6", node_type="Sandbox", label="Browser Sandbox & Detonation", position_x=850, position_y=150),
                WorkflowNode(node_id="n7", node_type="RiskScoring", label="Multi-Dimensional Risk Engine", position_x=1050, position_y=150),
                WorkflowNode(node_id="n8", node_type="HumanApproval", label="Policy Safety Gate (Autonomy L1)", position_x=1250, position_y=150)
            ],
            edges=[
                WorkflowEdge(edge_id="e1", source_node="n1", target_node="n2"),
                WorkflowEdge(edge_id="e2", source_node="n2", target_node="n3"),
                WorkflowEdge(edge_id="e3", source_node="n2", target_node="n4"),
                WorkflowEdge(edge_id="e4", source_node="n3", target_node="n5"),
                WorkflowEdge(edge_id="e5", source_node="n4", target_node="n5"),
                WorkflowEdge(edge_id="e6", source_node="n5", target_node="n6"),
                WorkflowEdge(edge_id="e7", source_node="n6", target_node="n7"),
                WorkflowEdge(edge_id="e8", source_node="n7", target_node="n8")
            ]
        )
        self._workflows[default_wf.workflow_id] = default_wf

    def list_agents(self) -> List[AgentConfig]:
        return list(self._agents.values())

    def get_agent(self, agent_id: str) -> Optional[AgentConfig]:
        return self._agents.get(agent_id)

    def save_agent(self, config: AgentConfig) -> AgentConfig:
        self._agents[config.agent_id] = config
        return config

    def list_rules(self) -> List[DetectionRule]:
        return list(self._rules.values())

    def save_rule(self, rule: DetectionRule) -> DetectionRule:
        self._rules[rule.rule_id] = rule
        return rule

    def list_workflows(self) -> List[InvestigationWorkflow]:
        return list(self._workflows.values())

    def save_workflow(self, workflow: InvestigationWorkflow) -> InvestigationWorkflow:
        self._workflows[workflow.workflow_id] = workflow
        return workflow
