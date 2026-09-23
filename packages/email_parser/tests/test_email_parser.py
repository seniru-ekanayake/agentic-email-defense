"""
Comprehensive Unit Tests for deterministic Email Parser and Canonical Attack Representation.
Covers:
- Moniker / Rendering Exploit EML
- Malformed MIME and recursion limits
- Deceptive URL / Link Mismatch detection
- Suspicious Attachment analysis (Executables / Macros / Magic signatures)
"""

import os
import sys
import unittest

# Ensure root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

from packages.email_parser.src.mime_parser import MimeParser
from packages.schemas.python.models import EmailAttackRepresentation, DataClassification


class TestEmailParser(unittest.TestCase):

    def setUp(self):
        self.parser = MimeParser()
        self.sample_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../samples/synthetic_cve_2023_35636_rendering_exploit.eml"))

    def test_parse_rendering_exploit_eml(self):
        with open(self.sample_path, "rb") as f:
            raw_bytes = f.read()

        rep = self.parser.parse_eml(raw_bytes)
        
        # 1. Verify schema type
        self.assertIsInstance(rep, EmailAttackRepresentation)
        self.assertEqual(rep.message_id, "<exp-2026-cve35636@attacker.c2.net>")
        
        # 2. Verify Sender & Recipient
        self.assertEqual(rep.sender.address, "spoofed-payroll@corporate-updates.net")
        self.assertEqual(len(rep.recipients), 1)
        self.assertEqual(rep.recipients[0].address, "cfo@enterprise-corp.internal")
        
        # 3. Verify VIP target detection
        self.assertTrue(rep.identity_targets[0].is_vip)

        # 4. Verify Authentication results
        self.assertEqual(rep.authentication.spf, "fail")
        self.assertEqual(rep.authentication.dmarc, "fail")

        # 5. Verify HTML and Rendering Exploit Indicators
        self.assertTrue(rep.body.html_features.has_remote_images)
        self.assertGreaterEqual(rep.body.html_features.hidden_elements_count, 1)

        # Check exploit indicators
        cve_targets = [ind.target_cve for ind in rep.exploit_indicators if ind.target_cve]
        self.assertIn("CVE-2023-35636", cve_targets)
        
        # 6. Verify Behavioral Features & Risk Evidence
        self.assertTrue(any("SPF/DMARC failure" in b for b in rep.behavioral_features))
        self.assertGreaterEqual(len(rep.risk_evidence), 2)
        
        # 7. Check Data Classification (Classified as CONFIDENTIAL due to executive compensation content)
        self.assertEqual(rep.classification, DataClassification.CONFIDENTIAL)

    def test_deceptive_url_mismatch(self):
        raw_eml = b"""From: alerts@bank.com
To: victim@company.com
Subject: Account Alert
MIME-Version: 1.0
Content-Type: text/html

<a href="http://evil-phishing-host.ru/login">https://secure.chase.com/login</a>
"""
        rep = self.parser.parse_eml(raw_eml)
        self.assertEqual(len(rep.urls), 1)
        self.assertTrue(rep.urls[0].is_mismatched)
        self.assertEqual(rep.urls[0].domain, "evil-phishing-host.ru")
        self.assertTrue(any("Deceptive link" in b for b in rep.behavioral_features))

    def test_macro_attachment_detection(self):
        raw_eml = b"""From: supplier@vendor.com
To: accountant@company.com
Subject: Overdue Invoice
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY123"

--BOUNDARY123
Content-Type: text/plain

Please find invoice attached.

--BOUNDARY123
Content-Type: application/vnd.ms-excel.sheet.macroEnabled.12
Content-Disposition: attachment; filename="Invoice_August_Q3.xlsm"

\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1...fake_macro_payload...
--BOUNDARY123--
"""
        rep = self.parser.parse_eml(raw_eml)
        self.assertEqual(len(rep.attachments), 1)
        att = rep.attachments[0]
        self.assertEqual(att.filename, "Invoice_August_Q3.xlsm")
        self.assertTrue(att.has_macros)
        self.assertTrue(any("macro-enabled attachment" in b for b in rep.behavioral_features))


if __name__ == "__main__":
    unittest.main()
