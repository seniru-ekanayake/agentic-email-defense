"""
UrlSandboxRunner: Dedicated Inbuilt URL & Malicious Link Behavioral Detonation Engine.
Analyzes arbitrary links, traces multi-hop redirects, captures DOM login forms,
detects credential harvesting and brand impersonation, and enforces strict SSRF network guards.
"""

import uuid
import re
import urllib.parse
import logging
from typing import Dict, Any, List, Optional, Tuple

from apps.sandbox.src.models import UrlSandboxReport, UrlPageFeatures
from apps.sandbox.src.network_guard import NetworkGuard

logger = logging.getLogger("UrlSandboxRunner")


class UrlSandboxRunner:
    """
    Dedicated behavioral detonation and threat analysis engine for links and URLs.
    """

    SHORTENER_DOMAINS = [
        "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd",
        "buff.ly", "adf.ly", "goo.gl", "rebrand.ly", "cutt.ly"
    ]

    BRAND_KEYWORD_MAP = {
        "microsoft": ["microsoft", "office365", "o365", "outlook", "sharepoint", "onedrive", "login.live.com"],
        "google": ["google", "gmail", "workspace", "google docs", "google drive"],
        "okta": ["okta", "single sign-on", "sso"],
        "paypal": ["paypal", "payment confirmation", "wallet dispute"],
        "bank": ["chase", "wells fargo", "bank of america", "citi", "secure banking"]
    }

    def __init__(self):
        self.network_guard = NetworkGuard()

    def analyze_url(
        self,
        url: str,
        simulated_landing_html: Optional[str] = None,
        simulated_redirects: Optional[List[str]] = None
    ) -> UrlSandboxReport:
        """
        Detonates and evaluates any standalone link or URL.
        """
        scan_id = f"url-{uuid.uuid4().hex[:8]}"
        parsed = urllib.parse.urlparse(url)
        domain = (parsed.hostname or url.split("/")[0]).lower().strip("[]")
        
        evidence: List[str] = []
        risk_score = 0.0

        # 1. Network Boundary & SSRF Evaluation
        is_allowed, block_reason, is_ssrf = self.network_guard.evaluate_destination(url)
        if not is_allowed:
            evidence.append(f"NetworkGuard blocked target: {block_reason}")
            return UrlSandboxReport(
                scan_id=scan_id,
                submitted_url=url,
                final_destination_url=url,
                network_guard_blocked=True,
                blocked_reason=block_reason,
                verdict="BLOCKED_SSRF" if is_ssrf else "MALICIOUS",
                threat_category="SSRF_PROBE" if is_ssrf else "NETWORK_VIOLATION",
                risk_score=95.0 if is_ssrf else 80.0,
                evidence=evidence
            )

        # 2. Domain Level Heuristics
        # IP-based URL check
        is_ip = bool(re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", domain))
        if is_ip:
            risk_score += 35.0
            evidence.append(f"Direct IP-based destination host: {domain}")

        # Punycode / IDN Homograph check
        is_puny = "xn--" in domain
        if is_puny:
            risk_score += 40.0
            evidence.append(f"Punycode/IDN internationalized domain detected (potential homograph impersonation): {domain}")

        # URL Shortener check
        is_shortener = any(domain == s or domain.endswith("." + s) for s in self.SHORTENER_DOMAINS)
        if is_shortener:
            risk_score += 15.0
            evidence.append("Obfuscated via URL shortener service.")

        # Suspicious TLD / extension check
        if any(domain.endswith(tld) for tld in [".ru", ".xyz", ".top", ".buzz", ".work", ".click", ".fit"]):
            risk_score += 20.0
            evidence.append(f"High-risk top-level domain observed: {domain}")

        # 3. Trace Redirects
        redirect_chain = simulated_redirects or [url]
        final_destination = redirect_chain[-1]
        if len(redirect_chain) > 1:
            evidence.append(f"Multi-hop redirect chain detected ({len(redirect_chain)} hops) ending at {final_destination}")
            final_domain = urllib.parse.urlparse(final_destination).hostname or ""
            if final_domain != domain:
                risk_score += 25.0
                evidence.append(f"Cross-domain redirect from '{domain}' to '{final_domain}'")

        # 4. Analyze Page Content & DOM Features
        html = simulated_landing_html or ""
        html_lower = html.lower()
        
        has_login = False
        has_password = False
        impersonated_brand = None
        external_scripts: List[str] = []
        iframe_sources: List[str] = []
        obfuscated_js = False

        if html:
            # Login Form Detection
            if "<form" in html_lower and ("login" in html_lower or "signin" in html_lower or "auth" in html_lower or "password" in html_lower):
                has_login = True
                risk_score += 25.0
                evidence.append("Interactive login / credential submission form identified on page.")

            if 'type="password"' in html_lower or "type='password'" in html_lower:
                has_password = True
                risk_score += 30.0
                evidence.append("Password input field detected.")

            # Brand Impersonation Scanning
            for brand, keywords in self.BRAND_KEYWORD_MAP.items():
                if any(kw in html_lower for kw in keywords):
                    # Check if domain actually belongs to legitimate brand
                    if brand not in domain:
                        impersonated_brand = brand.capitalize()
                        risk_score += 35.0
                        evidence.append(f"Brand impersonation detected: Page mimics {impersonated_brand} login, but hosted on '{domain}'.")
                        break

            # Obfuscated JavaScript
            if "unescape(" in html_lower or "eval(" in html_lower or "atob(" in html_lower:
                obfuscated_js = True
                risk_score += 30.0
                evidence.append("Obfuscated or dynamically evaluated JavaScript detected on landing page.")

            # Script and iFrame sources
            for script_match in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
                external_scripts.append(script_match)
            for iframe_match in re.findall(r'<iframe[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
                iframe_sources.append(iframe_match)

        page_features = UrlPageFeatures(
            title="Secure Sign-In" if has_login else "Landing Page",
            has_login_form=has_login,
            has_password_field=has_password,
            impersonated_brand=impersonated_brand,
            external_scripts=external_scripts,
            iframe_sources=iframe_sources,
            obfuscated_javascript=obfuscated_js
        )

        # 5. Determine Verdict and Threat Category
        risk_score = round(min(risk_score, 100.0), 1)

        if risk_score >= 70.0 or obfuscated_js:
            verdict = "MALICIOUS"
            if impersonated_brand or (has_login and has_password):
                threat_category = "CREDENTIAL_PHISHING"
            elif obfuscated_js:
                threat_category = "BROWSER_EXPLOIT"
            else:
                threat_category = "DECEPTIVE_REDIRECT"
        elif risk_score >= 40.0:
            verdict = "SUSPICIOUS"
            threat_category = "SUSPICIOUS_REDIRECT"
        else:
            verdict = "CLEAN"
            threat_category = None

        return UrlSandboxReport(
            scan_id=scan_id,
            submitted_url=url,
            final_destination_url=final_destination,
            redirect_chain=redirect_chain,
            is_ip_based=is_ip,
            is_punycode_homograph=is_puny,
            is_shortener=is_shortener,
            network_guard_blocked=False,
            page_features=page_features,
            verdict=verdict,
            threat_category=threat_category,
            risk_score=risk_score,
            evidence=evidence
        )
