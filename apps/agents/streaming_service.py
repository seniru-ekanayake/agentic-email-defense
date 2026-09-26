"""Real-Time Agent Reasoning SSE Stream Service.

Asynchronously streams agent thought progression, dynamic skill activations,
MCP tool executions, and gated response proposals as Server-Sent Events (SSE).
"""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
from typing import Any, AsyncGenerator, Dict, List, Optional
from pydantic import BaseModel, Field

from packages.schemas.python.models import SecurityState
from apps.agents.nodes.ingestion_node import IngestionNode
from apps.agents.nodes.email_analysis_node import EmailAnalysisNode
from apps.agents.nodes.vuln_research_node import VulnResearchNode
from apps.agents.nodes.exposure_node import ExposureNode
from apps.agents.nodes.investigation_node import InvestigationNode
from apps.agents.nodes.response_node import ResponseNode

logger = logging.getLogger("streaming_service")


class AgentEvent(BaseModel):
    """Structured SSE event broadcast to the SOC Dashboard."""

    event_type: str  # stage_start, thought, skill_activated, mcp_tool, evidence, proposal, complete
    stage: str       # INGESTION, ANALYSIS, VULN_RESEARCH, EXPOSURE, INVESTIGATION, RESPONSE
    message: str
    data: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    def to_sse_line(self) -> str:
        """Format as standard Server-Sent Event data frame."""
        return f"event: {self.event_type}\ndata: {self.model_dump_json()}\n\n"


class SecurityGraphStreamer:
    """Streams the multi-node LangGraph execution with intermediate observability."""

    def __init__(self):
        self.ingestion_node = IngestionNode()
        self.email_analysis_node = EmailAnalysisNode()
        self.vuln_research_node = VulnResearchNode()
        self.exposure_node = ExposureNode()
        self.investigation_node = InvestigationNode()
        self.response_node = ResponseNode()

    async def stream_execution(self, initial_state: SecurityState) -> AsyncGenerator[AgentEvent, None]:
        """Asynchronously execute each agent node, yielding real-time telemetry events."""
        state = initial_state
        tenant_id = state.get("tenant_id", "tenant-default")

        # --- Stage 1: Ingestion & Privacy Boundary ---
        yield AgentEvent(
            event_type="stage_start",
            stage="INGESTION",
            message=f"Starting email perimeter ingestion for tenant '{tenant_id}'...",
            data={"tenant_id": tenant_id}
        )
        await asyncio.sleep(0.01)  # Yield to event loop
        state = await asyncio.to_thread(self.ingestion_node.execute, state)
        
        yield AgentEvent(
            event_type="thought",
            stage="INGESTION",
            message="Data privacy boundary evaluated. Payload classified and routed.",
            data={"classification": state.get("classification", "INTERNAL")}
        )

        # --- Stage 2: Email Analysis & Dynamic Skill Activation ---
        yield AgentEvent(
            event_type="stage_start",
            stage="ANALYSIS",
            message="Executing MIME parsing and behavioral sandbox observation...",
            data={"message_id": state.get("email_representation", {}).get("message_id")}
        )
        await asyncio.sleep(0.01)
        state = await asyncio.to_thread(self.email_analysis_node.execute, state)

        active_skills = state.get("activated_skills", [])
        if active_skills:
            for skill in active_skills:
                yield AgentEvent(
                    event_type="skill_activated",
                    stage="ANALYSIS",
                    message=f"Dynamically activated forensic playbook: '{skill}'",
                    data={"skill_name": skill}
                )

        # --- Stage 3: Vulnerability & Threat Intelligence Research ---
        yield AgentEvent(
            event_type="stage_start",
            stage="VULN_RESEARCH",
            message="Correlating threat indicators with CISA KEV, NVD, and MITRE ATT&CK...",
            data={}
        )
        await asyncio.sleep(0.01)
        state = await asyncio.to_thread(self.vuln_research_node.execute, state)

        vuln_ctx = state.get("vulnerability_context", [])
        if vuln_ctx:
            cve_id = vuln_ctx[0].get("cve", "CVE-UNKNOWN")
            yield AgentEvent(
                event_type="evidence",
                stage="VULN_RESEARCH",
                message=f"Identified high-exploitability vulnerability: {cve_id}",
                data={"cve": cve_id, "assessment": vuln_ctx[0]}
            )

        # --- Stage 4: Exposure & Attack Surface Correlation ---
        yield AgentEvent(
            event_type="stage_start",
            stage="EXPOSURE",
            message="Evaluating attack surface exposure on target mail infrastructure...",
            data={}
        )
        await asyncio.sleep(0.01)
        state = await asyncio.to_thread(self.exposure_node.execute, state)

        # --- Stage 5: Investigation & Campaign Deduplication ---
        yield AgentEvent(
            event_type="stage_start",
            stage="INVESTIGATION",
            message="Synthesizing multi-dimensional risk scores and clustering campaigns...",
            data={}
        )
        await asyncio.sleep(0.01)
        state = await asyncio.to_thread(self.investigation_node.execute, state)

        camp_ctx = state.get("campaign_context", {})
        if camp_ctx:
            yield AgentEvent(
                event_type="thought",
                stage="INVESTIGATION",
                message=f"Campaign cluster: {camp_ctx.get('campaign_id')} (Total: {camp_ctx.get('total_emails_in_campaign')} emails, {camp_ctx.get('unique_recipients_count')} targets)",
                data=camp_ctx
            )

        # --- Stage 6: Response Planning & Policy Gating ---
        yield AgentEvent(
            event_type="stage_start",
            stage="RESPONSE",
            message="Evaluating tenant autonomy levels and generating response proposals...",
            data={"autonomy_level": state.get("autonomy_level", 1)}
        )
        await asyncio.sleep(0.01)
        state = await asyncio.to_thread(self.response_node.execute, state)

        proposed_tools = state.get("proposed_tools", [])
        for prop in proposed_tools:
            yield AgentEvent(
                event_type="proposal",
                stage="RESPONSE",
                message=f"Response Proposal: {prop.get('tool_name')} - Reasoning: {prop.get('reasoning')}",
                data=prop
            )

        # --- Workflow Complete ---
        incident = state.get("incident_report", {})
        yield AgentEvent(
            event_type="complete",
            stage="RESPONSE",
            message=f"Triage complete. Incident created: '{incident.get('title')}' (Score: {incident.get('overall_risk_score')})",
            data={
                "incident_title": incident.get("title"),
                "severity": incident.get("severity"),
                "overall_risk_score": incident.get("overall_risk_score"),
                "confidence": state.get("confidence"),
                "incident_report": incident,
                "pending_approvals": state.get("pending_approvals", []),
                "executed_responses": state.get("executed_responses", [])
            }
        )

