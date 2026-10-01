"""
Deterministic HTML Analyzer for email bodies.
Extracts active content, rendering indicators, monikers, parser anomalies, and URLs
using centralized URLNormalizer and UnicodeSecurityAnalyzer without relying on an LLM.
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
from packages.email_parser.src.url_normalizer import URLNormalizer, NormalizedUrl
from packages.email_parser.src.unicode_analyzer import UnicodeSecurityAnalyzer


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

    def __init__(self):
        self.unicode_analyzer = UnicodeSecurityAnalyzer()

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

        urls: List[UrlFeature] = []
        exploit_indicators: List[ExploitIndicator] = []
        rendering_features: List[str] = []

        rfc2606_domains = {".invalid", ".example", ".test", ".localhost", "example.com", "example.org", "example.net"}

        # 1. Process HTML Links with URLNormalizer
        for href, text in parser.links:
            norm = URLNormalizer.normalize(href)
            domain = norm.host

            is_ip = bool(re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?$", domain))
            is_puny = "xn--" in domain
            is_test_domain = any(domain.endswith(td) for td in rfc2606_domains)

            # Check mismatch (e.g. text says paypal.com, href is evil.com)
            is_mismatched = False
            if text and ("http://" in text or "https://" in text or ".com" in text or ".org" in text):
                text_clean = text.replace("http://", "").replace("https://", "").split("/")[0].lower()
                if domain and text_clean and domain != text_clean and not domain.endswith("." + text_clean):
                    is_mismatched = True

            reputation = "inert_test_domain" if is_test_domain else ("suspicious" if (is_mismatched or is_ip or is_puny or norm.is_moniker_uri or norm.is_unc_path) else "unknown")

            urls.append(
                UrlFeature(
                    url=norm.normalized_url,
                    domain=domain or norm.scheme or "local/scheme",
                    display_text=text or None,
                    is_mismatched=is_mismatched,
                    is_ip_based=is_ip,
                    is_punycode=is_puny,
                    reputation=reputation
                )
            )

            # Flag Moniker URIs, UNC Paths, and Data URIs as explicit evidence (without hardcoded CVEs)
            if norm.is_moniker_uri:
                rendering_features.append(f"Moniker URI handler observed: {norm.scheme}:...")
                exploit_indicators.append(
                    ExploitIndicator(
                        indicator_type="MONIKER_URI_OBSERVED",
                        evidence=f"Observed moniker protocol scheme '{norm.scheme}' in normalized link: {norm.normalized_url[:80]}",
                        target_software="Windows Shell / Mail Client URI Handler",
                        target_cve=None,  # CVE correlation performed dynamically via threat intel/KEV
                        confidence=0.90
                    )
                )
            elif norm.is_unc_path:
                rendering_features.append(f"UNC / SMB remote path observed: {norm.normalized_url[:60]}")
                exploit_indicators.append(
                    ExploitIndicator(
                        indicator_type="UNC_PATH_OBSERVED",
                        evidence=f"Observed UNC remote share path: {norm.normalized_url[:80]}",
                        target_software="Windows SMB Client",
                        target_cve=None,
                        confidence=0.90
                    )
                )
            elif norm.is_data_uri:
                rendering_features.append("Inline data: URI payload observed")
                exploit_indicators.append(
                    ExploitIndicator(
                        indicator_type="DATA_URI_PAYLOAD_OBSERVED",
                        evidence=f"Inline data: URI payload: {norm.normalized_url[:60]}...",
                        target_software="Browser / Webmail Client",
                        target_cve=None,
                        confidence=0.85
                    )
                )

        # 2. Plain text URL scanning with URLNormalizer
        # Match http(s), file, search-ms, data, or percent-encoded versions
        raw_matches = re.findall(r"(?:https?|file|search-ms|data|%66%69%6c%65|%73%65%61%72%63%68)://[^\s<>\"'()]+", html_content, re.IGNORECASE)
        # Also check for unanchored search-ms: or file: schemes
        raw_matches += re.findall(r"(?:search-ms|file|ms-appinstaller):[^\s<>\"'()]+", html_content, re.IGNORECASE)

        existing_urls = {u.url for u in urls}
        for rmatch in raw_matches:
            norm = URLNormalizer.normalize(rmatch)
            if norm.normalized_url not in existing_urls:
                existing_urls.add(norm.normalized_url)
                p_domain = norm.host
                is_test = any(p_domain.endswith(td) for td in rfc2606_domains)
                urls.append(
                    UrlFeature(
                        url=norm.normalized_url,
                        domain=p_domain or norm.scheme or "bare/url",
                        display_text=rmatch,
                        is_mismatched=False,
                        is_ip_based=bool(re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?$", p_domain)),
                        is_punycode="xn--" in p_domain,
                        reputation="inert_test_domain" if is_test else "unknown"
                    )
                )
                if norm.is_moniker_uri or norm.is_unc_path:
                    exploit_indicators.append(
                        ExploitIndicator(
                            indicator_type="MONIKER_URI_OBSERVED" if norm.is_moniker_uri else "UNC_PATH_OBSERVED",
                            evidence=f"Observed protocol scheme '{norm.scheme}' in plain text: {norm.normalized_url[:80]}",
                            target_software="Windows Shell / Mail Client Handler",
                            target_cve=None,
                            confidence=0.90
                        )
                    )

        # 3. Unicode Anomaly Inspection (Body text)
        u_report = self.unicode_analyzer.analyze_text(html_content, "BODY: text/html")
        for finding in u_report:
            exploit_indicators.append(
                ExploitIndicator(
                    indicator_type=f"UNICODE_{finding.anomaly_type}",
                    evidence=f"{finding.description} (Location: {finding.location})",
                    target_software="Email Client / Visual Parser",
                    target_cve=None,
                    confidence=0.95
                )
            )
            rendering_features.append(f"Unicode anomaly ({finding.anomaly_type}) at {finding.location}")

        # 4. Script & Form active content checks
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
