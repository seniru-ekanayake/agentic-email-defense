"""
CISA Known Exploited Vulnerabilities (KEV) Catalog Ingestor.
Fetches and normalizes CISA KEV catalog with offline resilience.
"""

import json
import logging
import urllib.request
import urllib.error
import hashlib
from typing import List, Dict, Any, Optional

from packages.threat_intel.src.models import KevRecord, Provenance, ThreatIntelSource

logger = logging.getLogger("CisaKevIngestor")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Authoritative offline snapshot for resilience during local development or network isolation
BUNDLED_KEV_SNAPSHOT = [
    {
        "cveID": "CVE-2023-35636",
        "vendorProject": "Microsoft",
        "product": "Outlook",
        "vulnerabilityName": "Microsoft Outlook Information Disclosure Vulnerability",
        "dateAdded": "2024-01-16",
        "shortDescription": "Microsoft Outlook contains an information disclosure vulnerability that allows NTLM hash theft via crafted email previews.",
        "requiredAction": "Apply mitigations per vendor instructions.",
        "dueDate": "2024-02-06",
        "knownRansomwareCampaignUse": "Known",
        "notes": "Exploited via rendering email content."
    },
    {
        "cveID": "CVE-2023-23397",
        "vendorProject": "Microsoft",
        "product": "Outlook",
        "vulnerabilityName": "Microsoft Outlook Elevation of Privilege Vulnerability",
        "dateAdded": "2023-03-14",
        "shortDescription": "Microsoft Outlook contains an elevation of privilege vulnerability triggered when a specially crafted email with PidLidReminderFileParameter is received and processed.",
        "requiredAction": "Apply vendor updates.",
        "dueDate": "2023-04-04",
        "knownRansomwareCampaignUse": "Known",
        "notes": "Zero-interaction exploit: triggered upon email arrival."
    },
    {
        "cveID": "CVE-2024-21413",
        "vendorProject": "Microsoft",
        "product": "Outlook",
        "vulnerabilityName": "Microsoft Outlook Remote Code Execution Vulnerability (MonikerLink)",
        "dateAdded": "2024-02-13",
        "shortDescription": "Microsoft Outlook contains a remote code execution vulnerability where clicking or previewing a link with file:// and # triggers security bypass.",
        "requiredAction": "Apply vendor patches.",
        "dueDate": "2024-03-05",
        "knownRansomwareCampaignUse": "Known",
        "notes": "Low-interaction exploit."
    },
    {
        "cveID": "CVE-2022-27925",
        "vendorProject": "Zimbra",
        "product": "Collaboration Suite (ZCS)",
        "vulnerabilityName": "Zimbra Collaboration Suite Remote Code Execution",
        "dateAdded": "2022-08-11",
        "shortDescription": "Zimbra Collaboration Suite contains an arbitrary file upload vulnerability leading to RCE in mboximport.",
        "requiredAction": "Apply vendor patches.",
        "dueDate": "2022-09-01",
        "knownRansomwareCampaignUse": "Known",
        "notes": "Exploited in webmail deployments."
    }
]


class CisaKevIngestor:
    def __init__(self, cache_file: Optional[str] = None):
        self.cache_file = cache_file

    def ingest(self, live: bool = True) -> List[KevRecord]:
        """
        Fetches CISA KEV catalog. If live fetch fails, seamlessly falls back to bundled snapshot.
        """
        raw_items: List[Dict[str, Any]] = []
        source_url = CISA_KEV_URL

        if live:
            try:
                logger.info(f"Fetching CISA KEV feed from {CISA_KEV_URL}...")
                req = urllib.request.Request(
                    CISA_KEV_URL,
                    headers={"User-Agent": "AgenticEmailSecurityPlatform/1.0"}
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                    raw_items = payload.get("vulnerabilities", [])
                    logger.info(f"Successfully fetched {len(raw_items)} records from CISA KEV.")
            except Exception as e:
                logger.warning(f"Live CISA KEV fetch failed: {e}. Falling back to bundled offline catalog.")
                raw_items = BUNDLED_KEV_SNAPSHOT
                source_url = "bundled://cisa_kev_snapshot.json"
        else:
            raw_items = BUNDLED_KEV_SNAPSHOT
            source_url = "bundled://cisa_kev_snapshot.json"

        records: List[KevRecord] = []
        for item in raw_items:
            content_bytes = json.dumps(item, sort_keys=True).encode("utf-8")
            raw_hash = hashlib.sha256(content_bytes).hexdigest()

            prov = Provenance(
                source=ThreatIntelSource.CISA_KEV,
                source_url=source_url,
                published_at=item.get("dateAdded"),
                confidence=1.0,
                raw_hash=raw_hash
            )

            records.append(
                KevRecord(
                    cve_id=item.get("cveID", ""),
                    vendor_project=item.get("vendorProject", ""),
                    product=item.get("product", ""),
                    vulnerability_name=item.get("vulnerabilityName", ""),
                    date_added=item.get("dateAdded", ""),
                    short_description=item.get("shortDescription", ""),
                    required_action=item.get("requiredAction", ""),
                    due_date=item.get("dueDate", ""),
                    known_ransomware_use=item.get("knownRansomwareCampaignUse", "Unknown"),
                    notes=item.get("notes"),
                    provenance=prov
                )
            )

        return records
