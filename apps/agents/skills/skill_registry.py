"""Dynamic Agentic Skill Engine & Skill Registry.

Loads, validates, and dynamically activates domain-specific forensic playbooks (SKILL.md)
based on incoming email attack representations and agent investigation state.
Prevents system prompt bloat by injecting only relevant investigation procedures on-demand.
"""

from __future__ import annotations

import os
import re
import logging
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from packages.schemas.python.models import EmailAttackRepresentation

logger = logging.getLogger("skills.skill_registry")


class SkillTrigger(BaseModel):
    uri_schemes: List[str] = Field(default_factory=list)
    cve_patterns: List[str] = Field(default_factory=list)
    keywords: List[str] = Field(default_factory=list)
    auth_failures: List[str] = Field(default_factory=list)
    requires_attachment: bool = False


class SkillMetadata(BaseModel):
    name: str
    description: str
    version: str = "1.0.0"
    author: str = "Agentic Defense Team"
    trigger: SkillTrigger = Field(default_factory=SkillTrigger)
    recommended_tools: List[str] = Field(default_factory=list)
    markdown_content: str = ""
    file_path: str = ""


class SkillRegistry:
    """Discovers and manages on-demand investigative skill playbooks."""

    def __init__(self, skills_dir: Optional[str] = None):
        if skills_dir is None:
            skills_dir = os.path.dirname(__file__)
        self.skills_dir = skills_dir
        self.skills: Dict[str, SkillMetadata] = {}
        self.discover_skills()

    def discover_skills(self) -> None:
        """Scan skills directory for subdirectories containing SKILL.md."""
        self.skills.clear()
        if not os.path.exists(self.skills_dir):
            return

        for entry in os.listdir(self.skills_dir):
            skill_folder = os.path.join(self.skills_dir, entry)
            skill_file = os.path.join(skill_folder, "SKILL.md")
            if os.path.isdir(skill_folder) and os.path.exists(skill_file):
                try:
                    meta = self._parse_skill_file(skill_file)
                    if meta:
                        self.skills[meta.name] = meta
                        logger.info(f"Loaded agentic skill: {meta.name} ({meta.description[:60]}...)")
                except Exception as exc:
                    logger.warning(f"Failed to parse skill at {skill_file}: {exc}")

    def _parse_skill_file(self, file_path: str) -> Optional[SkillMetadata]:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Parse YAML frontmatter if present
        if content.startswith("---"):
            parts = content.split("---", 2)
            if len(parts) >= 3:
                frontmatter_text = parts[1]
                body_text = parts[2].strip()
                
                # Simple robust key-value extraction from frontmatter
                name_match = re.search(r"^name:\s*(.+)$", frontmatter_text, re.MULTILINE)
                desc_match = re.search(r"^description:\s*(.+)$", frontmatter_text, re.MULTILINE)
                
                name = name_match.group(1).strip() if name_match else os.path.basename(os.path.dirname(file_path))
                description = desc_match.group(1).strip() if desc_match else ""

                # Parse triggers from body or frontmatter
                trigger = SkillTrigger()
                if "moniker" in name:
                    trigger.uri_schemes = ["search-ms", "file", "ms-appinstaller", "ms-word"]
                    trigger.cve_patterns = ["CVE-2024-21413", "CVE-2024-38021", "CVE-2023-35636"]
                elif "oauth" in name:
                    trigger.keywords = ["oauth", "authorize", "consent", "permissions", "login.microsoftonline.com", "accounts.google.com"]
                elif "dkim" in name or "spf" in name:
                    trigger.auth_failures = ["FAIL", "NEUTRAL", "SOFTFAIL", "PERMERROR"]
                elif "bec" in name or "financial" in name:
                    trigger.keywords = ["wire", "invoice", "bank", "routing", "swift", "payment", "urgent transfer", "direct deposit", "iban"]

                return SkillMetadata(
                    name=name,
                    description=description,
                    trigger=trigger,
                    markdown_content=body_text,
                    file_path=file_path,
                )
        return None

    def match_skills(self, ear: EmailAttackRepresentation) -> List[SkillMetadata]:
        """Evaluate an incoming email representation against skill triggers."""
        matched = []

        # 1. Check Moniker / URI / rendering exploits
        has_moniker = False
        for ind in ear.exploit_indicators:
            if "moniker" in ind.indicator_type.lower() or "cve-2024-21413" in (ind.target_cve or "").lower() or "search-ms" in ind.evidence.lower():
                has_moniker = True
                break

        for u in ear.urls:
            url_lower = u.url.lower()
            if any(url_lower.startswith(prefix) for prefix in ("search-ms:", "file://", "ms-appinstaller:", "ms-word:")):
                has_moniker = True
                break

        for rf in ear.rendering_features:
            if any(s in rf.lower() for s in ("search-ms", "file://", "moniker", "unc", "smb")):
                has_moniker = True
                break

        if has_moniker and "moniker_exploit_triage" in self.skills:
            matched.append(self.skills["moniker_exploit_triage"])

        # 2. Check OAuth consent abuse
        has_oauth = False
        for u in ear.urls:
            url_lower = u.url.lower()
            if any(k in url_lower for k in ("oauth", "consent", "authorize", "login.microsoftonline.com", "accounts.google.com")):
                has_oauth = True
                break

        if has_oauth and "oauth_consent_investigation" in self.skills and self.skills["oauth_consent_investigation"] not in matched:
            matched.append(self.skills["oauth_consent_investigation"])

        # 3. Check SPF / DKIM replay & auth failures
        auth_raw = (ear.authentication.auth_results_raw or "").lower() if ear.authentication else ""
        spf_val = (ear.authentication.spf or "").lower() if ear.authentication else ""
        dkim_val = (ear.authentication.dkim or "").lower() if ear.authentication else ""
        dmarc_val = (ear.authentication.dmarc or "").lower() if ear.authentication else ""

        if any(v in ("fail", "softfail", "neutral", "permerror") for v in (spf_val, dkim_val, dmarc_val)) or "fail" in auth_raw:
            if "dkim_spf_replay_analysis" in self.skills and self.skills["dkim_spf_replay_analysis"] not in matched:
                matched.append(self.skills["dkim_spf_replay_analysis"])

        # 4. Check BEC & Financial Urgency
        subject = ear.headers.get("Subject", ear.headers.get("subject", ""))
        body_text = (ear.body.text_plain or "") if ear.body else ""
        content_lower = f"{subject} {body_text}".lower()
        bec_terms = ["wire", "invoice", "bank", "routing", "swift", "payment", "urgent transfer", "direct deposit", "iban", "payroll"]
        if any(term in content_lower for term in bec_terms):
            if "bec_financial_recon" in self.skills and self.skills["bec_financial_recon"] not in matched:
                matched.append(self.skills["bec_financial_recon"])

        return matched

    def build_skill_prompt_context(self, active_skills: List[SkillMetadata]) -> str:
        """Render active skill playbooks into structured prompt context for agent execution."""
        if not active_skills:
            return ""

        sections = ["\n### ACTIVATED INVESTIGATION SKILLS & PROCEDURAL PLAYBOOKS:"]
        for s in active_skills:
            sections.append(f"\n#### [SKILL: {s.name.upper()}]\n{s.markdown_content}\n")
        return "\n".join(sections)
