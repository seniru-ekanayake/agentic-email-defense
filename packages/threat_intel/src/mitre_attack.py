"""
MITRE ATT&CK Ingestor and Mapping for Email Exploitation Tactics & Techniques.
"""

from typing import List, Dict, Optional
import hashlib
import json

from packages.threat_intel.src.models import MitreTechnique, Provenance, ThreatIntelSource

BUNDLED_MITRE_TECHNIQUES = [
    {
        "technique_id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Email Gateway", "File: File Creation", "Network Traffic: Network Traffic Flow"]
    },
    {
        "technique_id": "T1566.002",
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Email Gateway", "Network Traffic: Network Traffic Flow", "Application Log: Webmail Logs"]
    },
    {
        "technique_id": "T1187",
        "name": "Forced Authentication",
        "tactic": "Credential Access",
        "description": "Adversaries may gather credentials by forcing a client to automatically authenticate to an attacker-controlled server (e.g., via Outlook rendering monikers or search-ms URIs).",
        "platforms": ["Windows"],
        "data_sources": ["Logon Session: Logon Session Creation", "Network Traffic: Network Traffic Flow"]
    },
    {
        "technique_id": "T1204.001",
        "name": "User Execution: Malicious Link",
        "tactic": "Execution",
        "description": "An adversary may rely upon a user clicking a malicious link to trigger code execution or webmail session exploitation.",
        "platforms": ["Windows", "Linux", "macOS"],
        "data_sources": ["Process: Process Creation", "Network Traffic: Network Traffic Flow"]
    },
    {
        "technique_id": "T1114.002",
        "name": "Email Collection: Remote Email Collection",
        "tactic": "Collection",
        "description": "Adversaries may access user email repositories using legitimate webmail protocols or compromised OAuth/session tokens.",
        "platforms": ["Office 365", "Google Workspace", "Exchange"],
        "data_sources": ["Application Log: Mailbox Access", "Authentication: User Authentication"]
    }
]


class MitreAttackIngestor:
    def get_techniques(self) -> List[MitreTechnique]:
        techniques: List[MitreTechnique] = []
        for raw in BUNDLED_MITRE_TECHNIQUES:
            raw_hash = hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()
            prov = Provenance(
                source=ThreatIntelSource.MITRE_ATTACK,
                source_url="https://attack.mitre.org/",
                confidence=1.0,
                raw_hash=raw_hash
            )
            techniques.append(
                MitreTechnique(
                    technique_id=raw["technique_id"],
                    name=raw["name"],
                    tactic=raw["tactic"],
                    description=raw["description"],
                    platforms=raw["platforms"],
                    data_sources=raw["data_sources"],
                    provenance=prov
                )
            )
        return techniques

    def map_indicators_to_mitre(self, indicators: List[str]) -> List[MitreTechnique]:
        """Maps observed exploit indicators to relevant MITRE ATT&CK techniques."""
        all_techs = self.get_techniques()
        matched = []
        lower_indicators = [i.lower() for i in indicators]

        for tech in all_techs:
            if "forced" in tech.name.lower() or "auth" in tech.name.lower():
                if any("ntlm" in i or "moniker" in i or "smb" in i for i in lower_indicators):
                    matched.append(tech)
            elif "attachment" in tech.name.lower():
                if any("attachment" in i or "macro" in i or "executable" in i for i in lower_indicators):
                    matched.append(tech)
            elif "link" in tech.name.lower():
                if any("url" in i or "link" in i or "xss" in i for i in lower_indicators):
                    matched.append(tech)
            elif "collection" in tech.name.lower():
                if any("mailbox" in i or "session" in i or "forwarding" in i for i in lower_indicators):
                    matched.append(tech)

        return matched
