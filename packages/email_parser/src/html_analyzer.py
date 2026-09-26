"""
Deterministic HTML Analyzer for email bodies.
Extracts active content, rendering indicators, monikers, parser anomalies, and URLs without relying on an LLM.
"""

import re
import urllib.parse
from html.parser import HTMLParser
from typing import List, Dict, Any, Tuple, Optional

from packages.schemas.python.models import (
    HtmlFeatures,
    UrlFeature,
    ExploitIndicator
)


class HtmlExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags_found: List[str] = []
        self.links: List[Tuple[str, str]] = []  # (href, text)
        self.current_href: str = ""
        self.current_link_text: str = ""
        self.has_forms = False
        self.has_scripts = False
        self.has_iframes = False
        self.has_svg_xml = False
        self.has_external_css = False
        self.has_remote_images = False
        self.hidden_elements_count = 0
        self.suspicious_tags: List[str] = []
        self.extracted_text: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        tag_lower = tag.lower()
        self.tags_found.append(tag_lower)
        attr_dict = {k.lower(): v for k, v in attrs if v is not None}

        if tag_lower in ["script"]:
            self.has_scripts = True
            self.suspicious_tags.append("script")
        elif tag_lower in ["iframe"]:
            self.has_iframes = True
            self.suspicious_tags.append("iframe")
        elif tag_lower in ["object", "embed", "applet"]:
            self.suspicious_tags.append(tag_lower)
        elif tag_lower in ["svg", "xml", "math"]:
            self.has_svg_xml = True
        elif tag_lower in ["form"]:
            self.has_forms = True
        elif tag_lower in ["link"] and attr_dict.get("rel") == "stylesheet":
            self.has_external_css = True
        elif tag_lower in ["img"]:
            src = attr_dict.get("src", "")
            if src.startswith("http://") or src.startswith("https://") or src.startswith("\\\\"):
                self.has_remote_images = True

        # Check for hidden styles
        style = attr_dict.get("style", "").lower()
        if "display:none" in style or "visibility:hidden" in style or "font-size:0" in style or "opacity:0" in style:
            self.hidden_elements_count += 1

        # Check links
        if tag_lower == "a":
            self.current_href = attr_dict.get("href", "")
            self.current_link_text = ""

    def handle_data(self, data: str):
        self.extracted_text.append(data)
        if self.current_href:
            self.current_link_text += data

    def handle_endtag(self, tag: str):
        if tag.lower() == "a" and self.current_href:
            self.links.append((self.current_href.strip(), self.current_link_text.strip()))
            self.current_href = ""
            self.current_link_text = ""


class HtmlAnalyzer:
    """Deterministic analyzer for email HTML bodies."""

    MONIKER_PATTERNS = [
        (r"search-ms:[^\s\"'>]+", "CVE-2023-35636 Outlook Moniker / Search-ms URI Abuse"),
        (r"ms-appx:[^\s\"'>]+", "MS-APPX Protocol Execution Abuse"),
        (r"file://\\\\[^\s\"'>]+", "CVE-2024-21413 Outlook MonikerLink UNC Bypass"),
        (r"\\\\(?:[0-9]{1,3}\.){3}[0-9]{1,3}\\[^\s\"'>]+", "Forced SMB / UNC NTLM Hash Harvesting"),
        (r"\\\\(?:[a-zA-Z0-9_\-\.]+)\\[^\s\"'>]+", "Forced UNC Path Callout")
    ]

    def analyze(self, html_content: str) -> Tuple[HtmlFeatures, List[UrlFeature], List[ExploitIndicator], List[str]]:
        if not html_content:
            return HtmlFeatures(), [], [], []

        parser = HtmlExtractor()
        try:
            parser.feed(html_content)
        except Exception:
            pass

        html_features = HtmlFeatures(
            has_forms=parser.has_forms,
            has_scripts=parser.has_scripts,
            has_iframes=parser.has_iframes,
            has_svg_xml=parser.has_svg_xml,
            has_external_css=parser.has_external_css,
            has_remote_images=parser.has_remote_images,
            hidden_elements_count=parser.hidden_elements_count,
            suspicious_tags=list(set(parser.suspicious_tags))
        )

        # URL extraction and mismatch analysis
        urls: List[UrlFeature] = []
        rfc2606_domains = {".invalid", ".example", ".test", ".localhost", "example.com", "example.org", "example.net"}

        for href, text in parser.links:
            parsed = urllib.parse.urlparse(href)
            domain = parsed.netloc.lower()
            
            # Check IP-based
            is_ip = bool(re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?$", domain))
            # Check punycode
            is_puny = "xn--" in domain
            # Check RFC 2606 / RFC 6761 test domain
            is_test_domain = any(domain.endswith(td) for td in rfc2606_domains)
            # Check mismatch (e.g. text says paypal.com, href is evil.com)
            is_mismatched = False
            if text and ("http://" in text or "https://" in text or ".com" in text or ".org" in text):
                text_clean = text.replace("http://", "").replace("https://", "").split("/")[0].lower()
                if domain and text_clean and domain != text_clean and not domain.endswith("." + text_clean):
                    is_mismatched = True

            reputation = "inert_test_domain" if is_test_domain else ("suspicious" if (is_mismatched or is_ip or is_puny) else "unknown")

            urls.append(
                UrlFeature(
                    url=href,
                    domain=domain or "local/scheme",
                    display_text=text or None,
                    is_mismatched=is_mismatched,
                    is_ip_based=is_ip,
                    is_punycode=is_puny,
                    reputation=reputation
                )
            )

        # Exploit indicators and rendering anomalies
        exploit_indicators: List[ExploitIndicator] = []
        rendering_features: List[str] = []

        # Scan for Unicode Obfuscation, RTLO, Zero-Width Characters, and Homoglyphs
        rtlo_chars = re.findall(r"[\u202E\u202D\u2066\u2067\u2068\u2069]", html_content)
        if rtlo_chars:
            exploit_indicators.append(
                ExploitIndicator(
                    indicator_type="UNICODE_RTLO_OBFUSCATION",
                    evidence=f"Detected Right-to-Left Override (RTLO) Unicode control character(s): {[hex(ord(c)) for c in set(rtlo_chars)]}",
                    target_software="Email Client / Visual Parser",
                    target_cve=None,
                    confidence=0.98
                )
            )
            rendering_features.append("Unicode RTLO character detected (visual spoofing attempt).")

        zero_width = re.findall(r"[\u200B\u200C\u200D\uFEFF\u2060\u00AD]", html_content)
        if zero_width:
            exploit_indicators.append(
                ExploitIndicator(
                    indicator_type="UNICODE_ZERO_WIDTH_OBFUSCATION",
                    evidence=f"Detected {len(zero_width)} hidden zero-width / soft-hyphen character(s) used for NLP/filter evasion.",
                    target_software="NLP / Signature Gateway",
                    target_cve=None,
                    confidence=0.95
                )
            )
            rendering_features.append(f"Contains {len(zero_width)} zero-width/soft-hyphen characters for signature evasion.")

        # Cyrillic / Greek homoglyphs mixed into ASCII text
        mixed_homoglyphs = re.findall(r"[a-zA-Z0-9]+[\u0400-\u04FF\u0370-\u03FF]+[a-zA-Z0-9]*|[\u0400-\u04FF\u0370-\u03FF]+[a-zA-Z0-9]+", html_content)
        if mixed_homoglyphs:
            exploit_indicators.append(
                ExploitIndicator(
                    indicator_type="HOMOGLYPH_DECEPTIVE_TYPOGRAPHY",
                    evidence=f"Detected mixed-script Cyrillic/Greek homoglyph spoofing tokens: {mixed_homoglyphs[:5]}",
                    target_software="Visual Display / User Trust",
                    target_cve=None,
                    confidence=0.92
                )
            )
            rendering_features.append(f"Detected {len(mixed_homoglyphs)} mixed-script homoglyph tokens.")

        # Scan for Monikers / UNC / Rendering exploits in raw HTML
        for pattern, desc in self.MONIKER_PATTERNS:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for m in matches:
                rendering_features.append(f"Found URI handler: {m[:60]}")
                target_cve = "CVE-2023-35636" if "search-ms" in m else ("CVE-2024-21413" if "file:" in m else "T1187")
                exploit_indicators.append(
                    ExploitIndicator(
                        indicator_type="RENDERING_EXPLOIT_URI",
                        evidence=f"{desc} (Matched URI: {m})",
                        target_software="Microsoft Outlook / Webmail",
                        target_cve=target_cve,
                        confidence=0.95
                    )
                )

        if parser.has_scripts:
            exploit_indicators.append(
                ExploitIndicator(
                    indicator_type="ACTIVE_SCRIPTING",
                    evidence="Embedded <script> tag detected inside email HTML body.",
                    target_software="Webmail Client / Browser",
                    target_cve=None,
                    confidence=0.85
                )
            )

        if parser.has_forms:
            rendering_features.append("HTML contains interactive credential harvesting form.")

        return html_features, urls, exploit_indicators, rendering_features

