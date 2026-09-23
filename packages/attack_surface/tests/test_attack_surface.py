"""
Unit tests for Email Attack Surface Discovery and Multi-Dimensional Scoring Engine.
"""

import os
import sys
import unittest

# Ensure root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from packages.attack_surface.src.attack_surface_engine import EmailAttackSurfaceEngine
from packages.attack_surface.src.models import AssetState
from packages.email_parser.src.mime_parser import MimeParser
from packages.schemas.python.models import InteractionRequirement


class TestAttackSurfaceEngine(unittest.TestCase):

    def setUp(self):
        self.engine = EmailAttackSurfaceEngine()
        self.parser = MimeParser()
        self.sample_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../email_parser/samples/synthetic_cve_2023_35636_rendering_exploit.eml"))

    def test_domain_asset_discovery_and_fingerprinting(self):
        """Test asset discovery and adapter fingerprinting for Exchange / OWA."""
        simulated_headers = {"X-OWA-Version": "15.1.2507.17", "Server": "Microsoft-IIS/10.0"}
        simulated_html = '<a href="/owa/auth/logon.aspx">OWA Login</a>'

        assets = self.engine.discover_domain_assets(
            tenant_id="tenant-acme",
            domain="enterprise-corp.internal",
            simulated_headers=simulated_headers,
            simulated_html=simulated_html
        )

        self.assertGreater(len(assets), 0)
        asset = assets[0]
        
        # 1. Verify Product & Version
        self.assertEqual(asset.product, "Microsoft Exchange / Outlook Web Access (OWA)")
        self.assertEqual(asset.version, "15.1.2507.17")
        self.assertEqual(asset.webmail_path, "/owa")

        # 2. Verify Distinct Asset States (Never collapsed)
        self.assertIn(AssetState.ASSET_DISCOVERED, asset.states)
        self.assertIn(AssetState.ASSET_EXPOSED, asset.states)
        self.assertIn(AssetState.SOFTWARE_IDENTIFIED, asset.states)
        self.assertIn(AssetState.VERSION_IDENTIFIED, asset.states)
        self.assertIn(AssetState.VULNERABLE, asset.states)
        self.assertIn(AssetState.KNOWN_EXPLOITABLE, asset.states)
        self.assertIn(AssetState.EMAIL_DELIVERABLE_EXPLOIT_POSSIBLE, asset.states)

    def test_correlate_incoming_email_and_scoring(self):
        """Test correlation of incoming rendering exploit email with exposed asset."""
        simulated_headers = {"X-OWA-Version": "15.1.2507.17"}
        assets = self.engine.discover_domain_assets(
            tenant_id="tenant-acme",
            domain="enterprise-corp.internal",
            simulated_headers=simulated_headers
        )
        asset = assets[0]

        # Parse synthetic rendering exploit email
        with open(self.sample_path, "rb") as f:
            raw_eml = f.read()
        email_rep = self.parser.parse_eml(raw_eml)

        # Correlate
        scores = self.engine.correlate_incoming_email(asset, email_rep)

        # 1. Verify state transition
        self.assertIn(AssetState.ATTACK_OBSERVED, asset.states)

        # 2. Verify Multi-Dimensional Scores
        self.assertGreaterEqual(scores.exposure_score, 80.0)
        self.assertGreaterEqual(scores.exploitability_score, 80.0)
        self.assertEqual(scores.interaction_score, 90.0)  # Interaction: VIEW
        self.assertGreaterEqual(scores.identity_impact_score, 70.0)  # VIP CFO Target + NTLM theft
        self.assertGreaterEqual(scores.observed_attack_score, 90.0)
        self.assertGreaterEqual(scores.compromise_confidence, 0.85)
        
        # 3. Verify Severity
        self.assertIn(scores.severity, ["HIGH", "CRITICAL"])
        
        # 4. Verify Evidence transparency
        self.assertGreater(len(scores.evidence), 4)
        evidence_factors = [e["factor"] for e in scores.evidence]
        self.assertTrue(any("Interaction Requirement" in f for f in evidence_factors))
        self.assertTrue(any("VIP" in f for f in evidence_factors))


if __name__ == "__main__":
    unittest.main()
