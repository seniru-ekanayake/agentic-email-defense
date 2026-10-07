"""
CISA Known Exploited Vulnerabilities (KEV) Catalog Ingestor.
Fetches and normalizes CISA KEV catalog with offline resilience.
"""

import json
import os
import logging
import urllib.request
import urllib.error
import hashlib
from typing import List, Dict, Any, Optional

from packages.threat_intel.src.models import KevRecord, Provenance, ThreatIntelSource

logger = logging.getLogger("CisaKevIngestor")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Offline snapshot: a subset of the real CISA KEV catalog, shared with the CisaKevCorrelator tool.
# Regenerate with `python scripts/refresh_kev.py`.
KEV_DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "apps", "agents", "core", "data",
                                "known_exploited_vulnerabilities.json")


def _load_bundled_snapshot() -> list:
    try:
        with open(KEV_DATASET_PATH, "r", encoding="utf-8") as f:
            return json.load(f).get("vulnerabilities", [])
    except Exception as exc:
        logger.error(f"KEV snapshot unavailable at {KEV_DATASET_PATH}: {exc}")
        return []


BUNDLED_KEV_SNAPSHOT = _load_bundled_snapshot()


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
                source_url = "bundled://known_exploited_vulnerabilities.json"
        else:
            raw_items = BUNDLED_KEV_SNAPSHOT
            source_url = "bundled://known_exploited_vulnerabilities.json"

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
