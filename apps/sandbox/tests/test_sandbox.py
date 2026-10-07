"""
Unit tests for Isolated Behavioral Sandbox and NetworkGuard.
"""

import os
import sys
import unittest

# Ensure root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from apps.sandbox.src.network_guard import NetworkGuard
from packages.email_parser.src.mime_parser import MimeParser


class TestSandbox(unittest.TestCase):

    def setUp(self):
        self.guard = NetworkGuard()
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

if __name__ == "__main__":
    unittest.main()
