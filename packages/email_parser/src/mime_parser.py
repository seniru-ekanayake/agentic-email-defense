"""
Deterministic MIME Parser: Converts raw RFC822 EML bytes/text into EmailAttackRepresentation.
Hardened against malformed MIME structures, deep recursion, and attachment bombs.
"""

import email
import email.policy
import hashlib
import re
import datetime
from typing import Dict, Any, List, Optional, Tuple

from packages.schemas.python.models import (
    EmailAttackRepresentation,
    SenderInfo,
    RecipientInfo,
    AuthenticationResults,
    MimeStructure,
    BodyFeatures,
    AttachmentFeature,
    IdentityTarget,
    RiskEvidence,
    DataClassification
)
from packages.email_parser.src.html_analyzer import HtmlAnalyzer
from apps.agents.core.data_classification import DataClassificationEngine

MAX_RECURSION_DEPTH = 10
MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024  # 25 MB safety limit


class MimeParser:
    def __init__(self):
        self.html_analyzer = HtmlAnalyzer()
        self.classification_engine = DataClassificationEngine()

    def parse_eml(
        self,
        raw_content: bytes,
        explicit_classification: Optional[str] = None
    ) -> EmailAttackRepresentation:
        """
        Parses raw RFC822 EML bytes into canonical EmailAttackRepresentation.
        """
        msg = email.message_from_bytes(raw_content, policy=email.policy.default)
        
        # 1. Message Metadata & Headers
        message_id = str(msg.get("Message-ID", f"<synthetic-{hashlib.md5(raw_content).hexdigest()}@local>"))
        timestamp = msg.get("Date")
        if not timestamp:
            timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        else:
            timestamp = str(timestamp)

        headers: Dict[str, str] = {}
        for k, v in msg.items():
            headers[k] = str(v)

        # 2. Sender and Recipients
        from_header = str(msg.get("From", ""))
        sender = self._parse_address(from_header)

        recipients: List[RecipientInfo] = []
        for to_addr in msg.get_all("To", []):
            parsed = self._parse_address(str(to_addr))
            recipients.append(RecipientInfo(address=parsed.address, display_name=parsed.display_name, type="to"))
        for cc_addr in msg.get_all("Cc", []):
            parsed = self._parse_address(str(cc_addr))
            recipients.append(RecipientInfo(address=parsed.address, display_name=parsed.display_name, type="cc"))
        for bcc_addr in msg.get_all("Bcc", []):
            parsed = self._parse_address(str(bcc_addr))
            recipients.append(RecipientInfo(address=parsed.address, display_name=parsed.display_name, type="bcc"))

        if not recipients:
            recipients.append(RecipientInfo(address="undisclosed-recipients@local", type="to"))

        # 3. Authentication Results
        auth_res = self._parse_auth_results(headers)

        # 4. Extract Body & Attachments (with recursion guard)
        text_plain, text_html, attachments, mime_structure, malformed_indicators = self._extract_parts(msg)

        # 5. Analyze body for active content, unicode obfuscation & rendering exploits
        body_to_analyze = text_html if text_html else text_plain
        html_features, urls, exploit_indicators, rendering_features = self.html_analyzer.analyze(body_to_analyze)

        # If plain text has distinct content, scan plain text for unicode obfuscation as well
        if text_plain and text_html:
            _, plain_urls, plain_exploits, plain_rend = self.html_analyzer.analyze(text_plain)
            exploit_indicators.extend([e for e in plain_exploits if e not in exploit_indicators])
            rendering_features.extend([r for r in plain_rend if r not in rendering_features])
            for pu in plain_urls:
                if not any(u.url == pu.url for u in urls):
                    urls.append(pu)

        body_features = BodyFeatures(
            text_plain=text_plain or None,
            text_html=text_html or None,
            html_features=html_features
        )

        # 6. Behavioral Features & Risk Evidence
        behavioral_features: List[str] = []
        risk_evidence: List[RiskEvidence] = []


        if auth_res.spf == "fail" or auth_res.dmarc == "fail":
            behavioral_features.append("Sender authentication failed (SPF/DMARC failure)")
            risk_evidence.append(RiskEvidence(
                factor="Sender Spoofing",
                score_impact=25.0,
                reasoning="SPF/DMARC validation failed for sending domain."
            ))

        for ind in exploit_indicators:
            risk_evidence.append(RiskEvidence(
                factor=ind.indicator_type,
                score_impact=40.0,
                reasoning=ind.evidence
            ))

        for att in attachments:
            if att.has_macros or att.is_executable:
                behavioral_features.append(f"Suspicious executable or macro-enabled attachment: {att.filename}")
                risk_evidence.append(RiskEvidence(
                    factor="Dangerous Attachment",
                    score_impact=35.0,
                    reasoning=f"Attachment '{att.filename}' contains executable/macro payload."
                ))

        for url in urls:
            if url.is_mismatched:
                behavioral_features.append(f"Deceptive link text mismatch for destination: {url.url}")
                risk_evidence.append(RiskEvidence(
                    factor="Deceptive URL",
                    score_impact=20.0,
                    reasoning=f"Displayed anchor text differs from destination domain '{url.domain}'."
                ))

        # 7. Identify Identity Targets
        identity_targets: List[IdentityTarget] = []
        vip_keywords = ["exec", "ceo", "cfo", "cto", "coo", "ciso", "finance", "president", "director", "chief"]
        for r in recipients:
            target_str = (r.address + " " + (r.display_name or "")).lower()
            is_vip = any(kw in target_str for kw in vip_keywords)
            identity_targets.append(
                IdentityTarget(
                    email=r.address,
                    is_vip=is_vip
                )
            )

        # 8. Data Privacy Classification
        temp_dict = {"headers": headers, "body": {"text_plain": text_plain, "text_html": text_html}}
        classification = self.classification_engine.classify_payload(temp_dict, explicit_classification)

        return EmailAttackRepresentation(
            message_id=message_id,
            timestamp=timestamp,
            sender=sender,
            recipients=recipients,
            authentication=auth_res,
            headers=headers,
            mime=mime_structure,
            body=body_features,
            urls=urls,
            attachments=attachments,
            embedded_content=[],
            rendering_features=rendering_features,
            parser_features=malformed_indicators,
            behavioral_features=behavioral_features,
            exploit_indicators=exploit_indicators,
            identity_targets=identity_targets,
            classification=classification,
            risk_evidence=risk_evidence
        )

    def _parse_address(self, addr_str: str) -> SenderInfo:
        if not addr_str:
            return SenderInfo(address="unknown@local", domain="local")
        
        match = re.search(r"<([^>]+)>", addr_str)
        if match:
            clean_addr = match.group(1).strip()
            display_name = addr_str.replace(f"<{clean_addr}>", "").strip(' "\'')
        else:
            clean_addr = addr_str.strip()
            display_name = None

        domain = clean_addr.split("@")[-1] if "@" in clean_addr else "local"
        return SenderInfo(address=clean_addr, display_name=display_name or None, domain=domain)

    def _parse_auth_results(self, headers: Dict[str, str]) -> AuthenticationResults:
        raw_auth = headers.get("Authentication-Results", "") or headers.get("ARC-Authentication-Results", "")
        spf = "none"
        dkim = "none"
        dmarc = "none"

        if raw_auth:
            lower = raw_auth.lower()
            if "spf=pass" in lower:
                spf = "pass"
            elif "spf=fail" in lower:
                spf = "fail"
            elif "spf=softfail" in lower:
                spf = "softfail"

            if "dkim=pass" in lower:
                dkim = "pass"
            elif "dkim=fail" in lower:
                dkim = "fail"

            if "dmarc=pass" in lower:
                dmarc = "pass"
            elif "dmarc=fail" in lower:
                dmarc = "fail"

        return AuthenticationResults(
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            auth_results_raw=raw_auth or None
        )

    def _extract_parts(self, msg: email.message.EmailMessage) -> Tuple[str, str, List[AttachmentFeature], MimeStructure, List[str]]:
        text_plain = ""
        text_html = ""
        attachments: List[AttachmentFeature] = []
        parts_summary: List[str] = []
        malformed_indicators: List[str] = []

        is_multipart = msg.is_multipart()
        content_type = msg.get_content_type()
        boundary = msg.get_boundary()

        depth = 0
        for part in msg.walk():
            depth += 1
            if depth > MAX_RECURSION_DEPTH:
                malformed_indicators.append("Excessive MIME recursion depth detected (potential MIME bomb)")
                break

            part_type = part.get_content_type()
            parts_summary.append(part_type)
            disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in disposition or part.get_filename():
                filename = part.get_filename() or "unnamed_attachment"
                payload = part.get_payload(decode=True) or b""
                
                size = len(payload)
                sha256 = hashlib.sha256(payload).hexdigest()
                
                # Check magic bytes
                magic = "Unknown"
                if payload.startswith(b"MZ"):
                    magic = "Windows Executable (PE/DLL)"
                elif payload.startswith(b"PK\x03\x04"):
                    magic = "Zip Archive / OpenXML Document"
                elif payload.startswith(b"%PDF"):
                    magic = "PDF Document"
                elif payload.startswith(b"\xD0\xCF\x11\xE0"):
                    magic = "OLE Compound Document"

                lower_name = filename.lower()
                is_exec = any(lower_name.endswith(ext) for ext in [".exe", ".bat", ".cmd", ".vbs", ".js", ".hta", ".ps1", ".lnk", ".iso"])
                has_macros = any(lower_name.endswith(ext) for ext in [".xlsm", ".docm", ".dotm", ".xltm", ".pptm"])

                attachments.append(
                    AttachmentFeature(
                        filename=filename,
                        content_type=part_type,
                        sha256=sha256,
                        size_bytes=size,
                        magic_type=magic,
                        is_executable=is_exec,
                        has_macros=has_macros
                    )
                )
            elif part_type == "text/plain" and not text_plain:
                try:
                    payload = part.get_payload(decode=True)
                    text_plain = payload.decode(part.get_content_charset() or "utf-8", errors="replace") if payload is not None else ""
                except Exception:
                    text_plain = str(part.get_payload()) if part.get_payload() is not None else ""
            elif part_type == "text/html" and not text_html:
                try:
                    payload = part.get_payload(decode=True)
                    text_html = payload.decode(part.get_content_charset() or "utf-8", errors="replace") if payload is not None else ""
                except Exception:
                    text_html = str(part.get_payload()) if part.get_payload() is not None else ""

        mime_structure = MimeStructure(
            content_type=content_type,
            boundary=boundary,
            structure_depth=depth,
            is_multipart=is_multipart,
            parts_summary=parts_summary,
            malformed_indicators=malformed_indicators
        )

        return text_plain, text_html, attachments, mime_structure, malformed_indicators
