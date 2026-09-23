"""
Unit tests for Isolated Behavioral Sandbox and NetworkGuard.
"""

import os
import sys
import unittest

# Ensure root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from apps.sandbox.src.network_guard import NetworkGuard
from apps.sandbox.src.sandbox_runner import SandboxRunner
from packages.email_parser.src.mime_parser import MimeParser


class TestSandbox(unittest.TestCase):

    def setUp(self):
        self.guard = NetworkGuard()
        self.runner = SandboxRunner()
        self.parser = MimeParser()
        self.sample_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../packages/email_parser/samples/synthetic_cve_2023_35636_rendering_exploit.eml"))

    def test_network_guard_rfc1918_and_localhost(self):
        """Test blocking of private IP subnets and localhost."""
        # RFC1918 IPs
        allowed, reason, is_ssrf = self.guard.evaluate_destination("http://192.168.1.50/admin")
        self.assertFalse(allowed)
        self.assertTrue(is_ssrf)
        self.assertIn("RFC1918", reason)

        allowed, reason, is_ssrf = self.guard.evaluate_destination("http://10.0.0.1:8080/internal")
        self.assertFalse(allowed)
        self.assertTrue(is_ssrf)

        # Localhost
        allowed, reason, is_ssrf = self.guard.evaluate_destination("http://localhost:3000")
        self.assertFalse(allowed)
        self.assertTrue(is_ssrf)

        allowed, reason, is_ssrf = self.guard.evaluate_destination("http://127.0.0.1:5432")
        self.assertFalse(allowed)
        self.assertTrue(is_ssrf)

    def test_network_guard_cloud_metadata(self):
        """Test blocking AWS/GCP/Azure cloud metadata endpoints."""
        allowed, reason, is_ssrf = self.guard.evaluate_destination("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(allowed)
        self.assertTrue(is_ssrf)
        self.assertIn("Cloud Metadata", reason)

        allowed, reason, is_ssrf = self.guard.evaluate_destination("http://metadata.google.internal/computeMetadata/v1/")
        self.assertFalse(allowed)
        self.assertTrue(is_ssrf)

    def test_sandbox_rendering_exploit_observation(self):
        """Test behavioral telemetry extraction on synthetic rendering exploit email."""
        with open(self.sample_path, "rb") as f:
            raw_eml = f.read()
        email_rep = self.parser.parse_eml(raw_eml)

        telemetry = self.runner.run_safe_observation(email_rep)

        self.assertFalse(telemetry.is_benign)
        self.assertGreater(len(telemetry.rendering_anomalies), 0)
        self.assertTrue(any("search-ms" in a for a in telemetry.rendering_anomalies))
        self.assertGreater(len(telemetry.forced_callout_destinations), 0)
        self.assertTrue(any("198.51.100.42" in dest for dest in telemetry.forced_callout_destinations))
        self.assertGreater(telemetry.execution_duration_ms, 0)
        self.assertTrue(telemetry.execution_id.startswith("sbx-"))


if __name__ == "__main__":
    unittest.main()
