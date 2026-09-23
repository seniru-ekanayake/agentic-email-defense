"""
NVD (National Vulnerability Database) CVE Ingestor.
Fetches and normalizes CVE records, parsing CVSS v3.1 vectors, CPEs, and CWEs.
"""

import json
import logging
import urllib.request
import urllib.error
import hashlib
from typing import List, Dict, Any, Optional

from packages.threat_intel.src.models import CveRecord, Provenance, ThreatIntelSource

logger = logging.getLogger("NvdIngestor")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Bundled offline high-priority email exploitation CVEs for immediate local testing & resilience
BUNDLED_NVD_CVE_SNAPSHOT = [
    {
        "cve": {
            "id": "CVE-2023-35636",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Microsoft Outlook Information Disclosure Vulnerability due to improper parsing of search-ms URIs in preview rendering."
                }
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                            "baseScore": 6.5,
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "NONE",
                            "userInteraction": "REQUIRED"
                        }
                    }
                ]
            },
            "weaknesses": [{"description": [{"value": "CWE-200"}]}],
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"criteria": "cpe:2.3:a:microsoft:outlook:2016:*:*:*:*:*:*:*", "vulnerable": True},
                                {"criteria": "cpe:2.3:a:microsoft:outlook:2019:*:*:*:*:*:*:*", "vulnerable": True},
                                {"criteria": "cpe:2.3:a:microsoft:outlook:2021:*:*:*:*:*:*:*", "vulnerable": True}
                            ]
                        }
                    ]
                }
            ]
        }
    },
    {
        "cve": {
            "id": "CVE-2023-23397",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Microsoft Outlook Elevation of Privilege Vulnerability triggered by specially crafted calendar/reminder email without user interaction."
                }
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8,
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "NONE",
                            "userInteraction": "NONE"
                        }
                    }
                ]
            },
            "weaknesses": [{"description": [{"value": "CWE-287"}]}],
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"criteria": "cpe:2.3:a:microsoft:outlook:*:*:*:*:*:*:*:*", "vulnerable": True}
                            ]
                        }
                    ]
                }
            ]
        }
    },
    {
        "cve": {
            "id": "CVE-2022-27925",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Zimbra Collaboration Suite (ZCS) Unauthenticated Remote Code Execution in /service/extension/backup/mboximport."
                }
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8,
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "NONE",
                            "userInteraction": "NONE"
                        }
                    }
                ]
            },
            "weaknesses": [{"description": [{"value": "CWE-434"}]}],
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"criteria": "cpe:2.3:a:zimbra:collaboration:8.8.15:*:*:*:*:*:*:*", "vulnerable": True},
                                {"criteria": "cpe:2.3:a:zimbra:collaboration:9.0.0:*:*:*:*:*:*:*", "vulnerable": True}
                            ]
                        }
                    ]
                }
            ]
        }
    }
]


class NvdIngestor:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key

    def fetch_cve(self, cve_id: str, live: bool = False) -> Optional[CveRecord]:
        """
        Fetches single CVE details from NVD or bundled offline snapshot.
        """
        raw_cve: Optional[Dict[str, Any]] = None
        source_url = f"{NVD_API_URL}?cveId={cve_id}"

        if live:
            try:
                headers = {"User-Agent": "AgenticEmailSecurityPlatform/1.0"}
                if self.api_key:
                    headers["apiKey"] = self.api_key
                req = urllib.request.Request(source_url, headers=headers)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    vulnerabilities = data.get("vulnerabilities", [])
                    if vulnerabilities:
                        raw_cve = vulnerabilities[0].get("cve")
            except Exception as e:
                logger.warning(f"Live NVD fetch failed for {cve_id}: {e}. Falling back to snapshot.")

        if not raw_cve:
            # Search snapshot
            for item in BUNDLED_NVD_CVE_SNAPSHOT:
                if item["cve"]["id"] == cve_id:
                    raw_cve = item["cve"]
                    source_url = f"bundled://nvd_cve_{cve_id}.json"
                    break

        if not raw_cve:
            return None

        return self._parse_nvd_cve(raw_cve, source_url)

    def _parse_nvd_cve(self, raw: Dict[str, Any], source_url: str) -> CveRecord:
        cve_id = raw.get("id", "")
        desc = ""
        for d in raw.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # CVSS v3.1 parsing
        cvss_data = {}
        metrics = raw.get("metrics", {})
        if "cvssMetricV31" in metrics and len(metrics["cvssMetricV31"]) > 0:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})

        # CPE parsing
        cpes = []
        for config in raw.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    crit = match.get("criteria")
                    if crit:
                        cpes.append(crit)

        # CWEs
        cwes = []
        for w in raw.get("weaknesses", []):
            for d in w.get("description", []):
                val = d.get("value")
                if val:
                    cwes.append(val)

        content_bytes = json.dumps(raw, sort_keys=True).encode("utf-8")
        raw_hash = hashlib.sha256(content_bytes).hexdigest()

        prov = Provenance(
            source=ThreatIntelSource.NVD,
            source_url=source_url,
            confidence=1.0,
            raw_hash=raw_hash
        )

        return CveRecord(
            cve_id=cve_id,
            description=desc,
            cvss_v3_score=cvss_data.get("baseScore"),
            cvss_v3_vector=cvss_data.get("vectorString"),
            attack_vector=cvss_data.get("attackVector"),
            user_interaction=cvss_data.get("userInteraction"),
            attack_complexity=cvss_data.get("attackComplexity"),
            privileges_required=cvss_data.get("privilegesRequired"),
            cpe_match=cpes,
            cwe_ids=cwes,
            provenance=prov
        )
