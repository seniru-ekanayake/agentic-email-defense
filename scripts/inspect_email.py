#!/usr/bin/env python3
"""
FishingMails - Email Security & Agentic Triage CLI
Usage: python scripts/inspect_email.py <path_to_email.eml> [--tenant <tenant_id>] [--autonomy <0-4>]
"""

import sys
import os
import argparse
import asyncio
import json
from datetime import datetime

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from apps.agents.streaming_service import SecurityGraphStreamer, AgentEvent
from packages.schemas.python.models import SecurityState


def print_banner():
    banner = """
===========================================================================
                      F I S H I N G M A I L S
        Autonomous Email Exploitation Detection & Response Platform
      "He sits by the mailstream. He sees the hook. He cuts the line."
===========================================================================
"""
    print(banner)



async def analyze_email_file(eml_path: str, tenant_id: str = "tenant-enterprise-demo", autonomy_level: int = 1):
    if not os.path.exists(eml_path):
        print(f"[!] Error: File not found: {eml_path}")
        sys.exit(1)

    with open(eml_path, "rb") as f:
        raw_eml = f.read()

    print(f"[*] Target File: {os.path.abspath(eml_path)} ({len(raw_eml)} bytes)")
    print(f"[*] Tenant ID:   {tenant_id}")
    print(f"[*] Autonomy:    Level {autonomy_level} (Tier 1 Deterministic Zero-LLM / Hybrid)")
    print("=" * 75)
    print(">>> INITIALIZING 6-NODE LANGGRAPH REASONING STREAM...")
    print("=" * 75)

    streamer = SecurityGraphStreamer()
    initial_state: SecurityState = {
        "tenant_id": tenant_id,
        "workflow_id": f"wf-{os.urandom(4).hex()}",
        "autonomy_level": autonomy_level,
        "raw_eml": raw_eml,
    }

    stage_icons = {
        "INGESTION": "[1/6] INGESTION",
        "ANALYSIS": "[2/6] STATIC & SANDBOX ANALYSIS",
        "VULN_RESEARCH": "[3/6] VULN RESEARCH & THREAT INTEL",
        "EXPOSURE": "[4/6] ATTACK SURFACE CORRELATION",
        "INVESTIGATION": "[5/6] ATTACK GRAPH INVESTIGATION",
        "RESPONSE": "[6/6] RESPONSE POLICY GATING",
    }

    final_event_data = {}

    async for event in streamer.stream_execution(initial_state):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        stage_label = stage_icons.get(event.stage, event.stage)

        if event.event_type == "stage_start":
            print(f"\n>> {stage_label}")
            print(f"  [{timestamp}] {event.message}")
        elif event.event_type == "thought":
            print(f"  [{timestamp}] [THOUGHT] {event.message}")
        elif event.event_type == "skill_activated":
            print(f"  [{timestamp}] [SKILL] {event.message}")
        elif event.event_type == "mcp_tool":
            print(f"  [{timestamp}] [MCP] {event.message}")
        elif event.event_type == "proposal":
            print(f"  [{timestamp}] [PROPOSAL] {event.message}")
        elif event.event_type == "complete":
            final_event_data = event.data
            print(f"\n[OK] [COMPLETED] {event.message}")

    # Final Summary Report Display
    print("\n" + "=" * 75)
    print("                    FORENSIC INCIDENT VERDICT                        ")
    print("=" * 75)
    incident = final_event_data.get("incident_report", {})
    if incident:
        print(f" Title:                {incident.get('title', 'N/A')}")
        print(f" Severity:             \033[1;31m{incident.get('severity', 'UNKNOWN')}\033[0m")
        print(f" Overall Risk Score:   {incident.get('overall_risk_score', 0):.1f} / 100")
        print(f" Confidence Rate:      {incident.get('confidence', 0) * 100:.1f}%")
        print(f" Target Identity:      {incident.get('target_identity', 'N/A')}")
        print(f" Mail Platform:        {incident.get('mail_platform', 'N/A')}")
        print(f" Exposure Status:      {incident.get('exposure_status', 'N/A')}")
        print(f" Interaction Required: \033[1;33m{incident.get('interaction_required', 'N/A')}\033[0m")
        print(f" Identified CVE:       \033[1;31m{incident.get('cve', 'None')}\033[0m")
        
        print("\n[*] Reconstructed Attack Chain:")
        for step in incident.get("attack_chain", []):
            print(f"   -> [{step.get('stage')}] {step.get('description')} (Conf: {step.get('confidence', 1.0):.2f})")

        print("\n[*] MITRE ATT&CK Mapping:")
        for tech in incident.get("mitre_techniques", []):
            tech_id = tech.get('technique_id') or tech.get('id') or 'T1566'
            tech_name = tech.get('technique_name') or tech.get('name') or 'Phishing'
            print(f"   * {tech_id}: {tech_name}")

        pending = final_event_data.get("pending_approvals", [])
        if pending:
            print("\n[*] Gated Containment Proposals (Human-in-the-Loop Required):")
            for p in pending:
                action_name = p.get('tool_name') or p.get('action') or 'Unknown'
                reason = p.get('reasoning') or p.get('reason') or 'Policy gated'
                params = p.get('parameters', {})
                print(f"   [LOCKED] Token:  {p.get('approval_token')}")
                print(f"            Action: {action_name} (Risk: {p.get('risk_level', 'MEDIUM')})")
                print(f"            Target: {params}")
                print(f"            Reason: {reason}")


    else:
        print(" [!] No explicit incident report produced.")
    print("=" * 75)


def main():
    print_banner()
    parser = argparse.ArgumentParser(description="FishingMails Email Exploitation Triage CLI")
    parser.add_argument("file", nargs="?", default="packages/email_parser/samples/synthetic_cve_2023_35636_rendering_exploit.eml",
                        help="Path to .eml file to inspect")
    parser.add_argument("--tenant", default="tenant-enterprise-demo", help="Tenant ID")
    parser.add_argument("--autonomy", type=int, default=1, help="Autonomy level (0-4)")
    args = parser.parse_args()

    asyncio.run(analyze_email_file(args.file, args.tenant, args.autonomy))


if __name__ == "__main__":
    main()
