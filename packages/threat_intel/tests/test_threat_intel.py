"""
Unit tests for Threat Intelligence Package:
- CISA KEV Ingestor
- NVD Ingestor
- MITRE ATT&CK Ingestor
- EmailExploitabilityAnalyzer (VIEW, NONE, CLICK scoring)
"""

import os
import sys
import unittest

# Ensure root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from packages.threat_intel.src.cisa_kev import CisaKevIngestor
from packages.threat_intel.src.nvd import NvdIngestor
from packages.threat_intel.src.mitre_attack import MitreAttackIngestor
from packages.threat_intel.src.exploitability_analyzer import EmailExploitabilityAnalyzer
from packages.schemas.python.models import InteractionRequirement


class TestThreatIntel(unittest.TestCase):

    def setUp(self):
        self.kev_ingestor = CisaKevIngestor()
        self.nvd_ingestor = NvdIngestor()
        self.mitre_ingestor = MitreAttackIngestor()
        self.analyzer = EmailExploitabilityAnalyzer()

    def test_cisa_kev_ingestion(self):
        records = self.kev_ingestor.ingest(live=False)
        cve_map = {r.cve_id: r for r in records}
        # The bundled snapshot is a subset of the real CISA catalog.
        self.assertIn("CVE-2023-23397", cve_map)
        self.assertIn("CVE-2024-21413", cve_map)
        self.assertEqual(cve_map["CVE-2024-21413"].date_added, "2025-02-06")
        # CVE-2023-35636 is a real Outlook CVE but is NOT in CISA KEV.
        self.assertNotIn("CVE-2023-35636", cve_map)
        self.assertIsNotNone(cve_map["CVE-2023-23397"].provenance.raw_hash)

    def test_nvd_ingestion_and_cvss(self):
        cve = self.nvd_ingestor.fetch_cve("CVE-2023-35636", live=False)
        self.assertIsNotNone(cve)
        self.assertEqual(cve.cve_id, "CVE-2023-35636")
        self.assertEqual(cve.attack_vector, "NETWORK")
        self.assertEqual(cve.user_interaction, "REQUIRED")
        self.assertGreater(len(cve.cpe_match), 0)

    def test_mitre_attack_mapping(self):
        techniques = self.mitre_ingestor.map_indicators_to_mitre(["forced smb ntlm auth", "view preview"])
        self.assertGreater(len(techniques), 0)
        tech_ids = [t.technique_id for t in techniques]
        self.assertIn("T1187", tech_ids)  # Forced Authentication

    def test_exploitability_assessment_view_interaction(self):
        """CVE-2023-35636 needs only rendering (VIEW) but has no KEV entry, so no known-exploitation impact is claimed."""
        cve = self.nvd_ingestor.fetch_cve("CVE-2023-35636", live=False)
        kev = {r.cve_id: r for r in self.kev_ingestor.ingest(live=False)}.get("CVE-2023-35636")
        self.assertIsNone(kev)

        assessment = self.analyzer.assess_cve(cve, kev)
        self.assertEqual(assessment.cve, "CVE-2023-35636")
        self.assertTrue(assessment.email_delivery_possible)
        self.assertTrue(assessment.rendering_required)
        self.assertEqual(assessment.interaction_required, InteractionRequirement.VIEW)
        self.assertNotIn("NTLM", assessment.session_impact)

    def test_exploitability_assessment_zero_click(self):
        """Verify CVE-2023-23397 is scored as Interaction: NONE (zero-click arrival)."""
        cve = self.nvd_ingestor.fetch_cve("CVE-2023-23397", live=False)
        kev_records = {r.cve_id: r for r in self.kev_ingestor.ingest(live=False)}
        kev = kev_records.get("CVE-2023-23397")

        assessment = self.analyzer.assess_cve(cve, kev)
        self.assertEqual(assessment.cve, "CVE-2023-23397")
        self.assertEqual(assessment.interaction_required, InteractionRequirement.NONE)
        self.assertTrue(assessment.email_delivery_possible)


if __name__ == "__main__":
    unittest.main()
