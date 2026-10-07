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
        "Microsoft": ["microsoft", "office 365", "office365", "outlook", "sharepoint", "onedrive"],
        "Google": ["google", "gmail"],
        "Okta": ["okta"],
        "PayPal": ["paypal"],
        "Apple": ["apple id", "icloud"],
        "DocuSign": ["docusign"],
    }

    # Registrable domains legitimately operated by each brand
    BRAND_DOMAINS = {
        "Microsoft": ["microsoft.com", "microsoftonline.com", "live.com", "office.com", "outlook.com", "sharepoint.com", "onedrive.com", "office365.com"],
        "Google": ["google.com", "gmail.com", "googleusercontent.com"],
        "Okta": ["okta.com", "oktapreview.com"],
        "PayPal": ["paypal.com"],
        "Apple": ["apple.com", "icloud.com"],
        "DocuSign": ["docusign.com", "docusign.net"],
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
        is_allowed, block_reason, is_ssrf = self.network_guard.evaluate_destination(url, resolve=simulated_landing_html is None and simulated_redirects is None)
        if not is_allowed and not is_ssrf and "does not resolve" in (block_reason or ""):
            evidence.append(f"Destination unreachable: {block_reason}")
            return UrlSandboxReport(
                scan_id=scan_id,
                submitted_url=url,
                final_destination_url=url,
                network_guard_blocked=False,
                blocked_reason=block_reason,
                verdict="UNREACHABLE",
                threat_category="UNREACHABLE",
                risk_score=0.0,
                evidence=evidence
            )
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
        for hop in redirect_chain:
            hop_allowed, hop_reason, hop_ssrf = self.network_guard.evaluate_destination(hop, resolve=simulated_landing_html is None and simulated_redirects is None)
            if not hop_allowed:
                evidence.append(f"NetworkGuard blocked redirect hop '{hop}': {hop_reason}")
                return UrlSandboxReport(
                    scan_id=scan_id,
                    submitted_url=url,
                    final_destination_url=hop,
                    network_guard_blocked=True,
                    blocked_reason=hop_reason,
                    verdict="BLOCKED_SSRF" if hop_ssrf else "MALICIOUS",
                    threat_category="SSRF_PROBE" if hop_ssrf else "NETWORK_VIOLATION",
                    risk_score=95.0 if hop_ssrf else 80.0,
                    evidence=evidence
                )

        final_destination = redirect_chain[-1]
        if len(redirect_chain) > 1:
            evidence.append(f"Multi-hop redirect chain detected ({len(redirect_chain)} hops) ending at {final_destination}")
            final_domain = urllib.parse.urlparse(final_destination).hostname or ""
            if final_domain != domain:
                risk_score += 25.0
                evidence.append(f"Cross-domain redirect from '{domain}' to '{final_domain}'")

        # 4. Fetch and Analyze Page Content & DOM Features
        html = simulated_landing_html
        execution_mode = "STATIC_FIXTURE_ANALYSIS" if simulated_landing_html is not None else "LIVE_STATIC_FETCH"
        
        # If no simulated landing HTML is provided, attempt live fetch if destination is safe
        if html is None:
            from apps.sandbox.src.safe_http import guarded_session
            try:
                session = guarded_session()
                current_url = final_destination
                redirect_count = 0
                max_redirects = 5
                
                while redirect_count < max_redirects:
                    resp = session.get(
                        current_url,
                        timeout=3.0,
                        headers={"User-Agent": "AgenticEmailDefense-UrlAnalyzer/1.0"},
                        allow_redirects=False
                    )
                    
                    if resp.is_redirect:
                        redirect_count += 1
                        next_url = urllib.parse.urljoin(current_url, resp.headers.get("Location", ""))
                        hop_allowed, hop_reason, hop_ssrf = self.network_guard.evaluate_destination(next_url, resolve=True)
                        if not hop_allowed:
                            evidence.append(f"NetworkGuard blocked dynamic redirect hop '{next_url}': {hop_reason}")
                            return UrlSandboxReport(
                                scan_id=scan_id,
                                submitted_url=url,
                                final_destination_url=next_url,
                                network_guard_blocked=True,
                                blocked_reason=hop_reason,
                                verdict="BLOCKED_SSRF" if hop_ssrf else "MALICIOUS",
                                threat_category="SSRF_PROBE" if hop_ssrf else "NETWORK_VIOLATION",
                                risk_score=95.0 if hop_ssrf else 80.0,
                                evidence=evidence
                            )
                        current_url = next_url
                        redirect_chain.append(current_url)
                    else:
                        break
                        
                final_destination = current_url
                
                if resp.status_code == 200:
                    html = resp.text[:100000]  # size limit 100KB
                    evidence.append(f"Retrieved live landing page ({len(html)} bytes, HTTP 200).")
                else:
                    evidence.append(f"HTTP GET returned status code {resp.status_code}.")
                    html = ""
            except Exception as net_err:
                if "Blocked connection to non-public address" in str(net_err):
                    evidence.append(f"Connection refused by SSRF guard: {net_err}")
                    return UrlSandboxReport(
                        scan_id=scan_id,
                        submitted_url=url,
                        final_destination_url=current_url,
                        network_guard_blocked=True,
                        blocked_reason="Destination resolved to a non-public address at connect time",
                        verdict="BLOCKED_SSRF",
                        threat_category="SSRF_PROBE",
                        risk_score=95.0,
                        evidence=evidence
                    )
                evidence.append(f"Static HTTP fetch failed: {net_err}")
                html = ""

        html = html or ""
        html_lower = html.lower()
        evidence.append("Analyzed via static HTTP fetch (no browser execution).")
        
        has_login = False
        has_password = False
        impersonated_brand = None
        external_scripts: List[str] = []
        iframe_sources: List[str] = []
        obfuscated_js = False

        if html:
            title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
            title_text = (title_match.group(1) if title_match else "").lower()
            forms = re.findall(r"<form\b.*?</form>", html, re.IGNORECASE | re.DOTALL)
            form_text = " ".join(forms).lower()

            has_password = 'type="password"' in form_text or "type='password'" in form_text or "type=password" in form_text
            has_login = bool(forms) and (has_password or any(k in form_text for k in ("login", "sign in", "signin")))
            if has_login:
                risk_score += 15.0
                evidence.append("Credential submission form present on page.")
            if has_password:
                risk_score += 15.0
                evidence.append("Password input field detected.")

            # Brand impersonation: a credential form branded as a company the host does not belong to.
            if has_login:
                final_host = (urllib.parse.urlparse(final_destination).hostname or domain).lower()
                for brand, keywords in self.BRAND_KEYWORD_MAP.items():
                    if any(kw in title_text or kw in form_text for kw in keywords):
                        legit = self.BRAND_DOMAINS.get(brand, [])
                        if not any(final_host == d or final_host.endswith("." + d) for d in legit):
                            impersonated_brand = brand
                            risk_score += 45.0
                            evidence.append(f"Credential form branded as {brand} on non-{brand} host '{final_host}'.")
                        break

            # Heavily obfuscated inline JavaScript (common minified JS alone is not a signal)
            inline_scripts = " ".join(re.findall(r"<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.IGNORECASE | re.DOTALL)).lower()
            if re.search(r"(eval|document\.write)\s*\(\s*(unescape|atob|decodeuricomponent)\s*\(", inline_scripts):
                obfuscated_js = True
                risk_score += 35.0
                evidence.append("Inline script decodes and evaluates an obfuscated payload.")

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

        if risk_score >= 70.0:
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
            evidence=evidence,
            browser_runtime_status="BROWSER_RUNTIME_UNAVAILABLE",
            execution_mode=execution_mode
        )
