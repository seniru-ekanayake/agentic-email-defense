"""
Zero-Cost Community Threat Intelligence Connectors.
Integrates free threat intelligence sources with full enterprise proxy support:
- HTTP_PROXY, HTTPS_PROXY, NO_PROXY, REQUESTS_CA_BUNDLE
- Strict TLS certificate verification (never disabled)
- Explicit network operational states: DIRECT, PROXY, TLS_ERROR, AUTH_ERROR, NETWORK_ERROR
"""

from __future__ import annotations

import os
import asyncio
import time
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import requests

from apps.sandbox.src.network_guard import NetworkGuard

logger = logging.getLogger("threat_intel.free_feeds")


def get_enterprise_session() -> Tuple[requests.Session, str]:
    """
    Configures a requests Session respecting enterprise proxy and CA bundle environment variables.
    Returns (session, proxy_state_label) where proxy_state_label is 'PROXY' or 'DIRECT'.
    """
    session = requests.Session()
    http_proxy = os.getenv("HTTP_PROXY") or os.getenv("http_proxy")
    https_proxy = os.getenv("HTTPS_PROXY") or os.getenv("https_proxy")
    no_proxy = os.getenv("NO_PROXY") or os.getenv("no_proxy")
    ca_bundle = os.getenv("REQUESTS_CA_BUNDLE") or os.getenv("CURL_CA_BUNDLE")

    state = "DIRECT"
    proxies = {}
    if http_proxy:
        proxies["http"] = http_proxy
        state = "PROXY"
    if https_proxy:
        proxies["https"] = https_proxy
        state = "PROXY"

    if proxies:
        session.proxies.update(proxies)

    if ca_bundle and os.path.exists(ca_bundle):
        session.verify = ca_bundle
    else:
        # Enforce strict TLS certificate verification
        session.verify = True

    return session, state


class ThreatIntelCache:
    """In-memory LRU cache with TTL for threat intelligence indicators."""

    def __init__(self, default_ttl_seconds: int = 3600):
        self.default_ttl = default_ttl_seconds
        self._cache: Dict[str, Dict[str, Any]] = {}

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        if key in self._cache:
            entry = self._cache[key]
            if time.time() < entry["expires_at"]:
                return entry["data"]
            del self._cache[key]
        return None

    def set(self, key: str, data: Dict[str, Any], ttl_seconds: Optional[int] = None) -> None:
        ttl = ttl_seconds or self.default_ttl
        self._cache[key] = {
            "data": data,
            "expires_at": time.time() + ttl,
        }

    def clear(self) -> None:
        self._cache.clear()


class URLhausConnector:
    """Free URLhaus (abuse.ch) API connector for malicious URL intelligence."""

    API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

    def __init__(self, cache: Optional[ThreatIntelCache] = None, timeout: float = 5.0):
        self.cache = cache or ThreatIntelCache()
        self.timeout = timeout
        self.network_guard = NetworkGuard()

    def query_url(self, target_url: str) -> Dict[str, Any]:
        """Check if a URL is actively listed in the URLhaus malware database."""
        cache_key = f"urlhaus:{target_url}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached

        is_allowed, reason, _ = self.network_guard.evaluate_destination(target_url)
        if not is_allowed:
            result = {
                "url": target_url,
                "query_status": "blocked_by_network_guard",
                "network_state": "BLOCKED",
                "is_malicious": False,
                "threat_type": None,
                "tags": [],
            }
            return result

        session, net_mode = get_enterprise_session()
        try:
            response = session.post(
                self.API_URL,
                data={"url": target_url},
                timeout=self.timeout,
                headers={"User-Agent": "AgenticEmailDefense-FreeFeed/1.0"},
            )
            if response.status_code == 200:
                data = response.json()
                query_status = data.get("query_status", "no_results")
                is_malicious = query_status == "ok" and data.get("url_status") in ("online", "offline")
                result = {
                    "url": target_url,
                    "query_status": query_status,
                    "network_state": net_mode,
                    "is_malicious": is_malicious,
                    "threat_type": data.get("threat", None),
                    "tags": data.get("tags", []),
                    "reporter": data.get("reporter", None),
                }
            elif response.status_code in (401, 403):
                result = {
                    "url": target_url,
                    "query_status": f"http_error_{response.status_code}",
                    "network_state": "AUTH_ERROR",
                    "is_malicious": False,
                    "threat_type": None,
                    "tags": [],
                }
            else:
                result = {
                    "url": target_url,
                    "query_status": f"http_error_{response.status_code}",
                    "network_state": "NETWORK_ERROR",
                    "is_malicious": False,
                    "threat_type": None,
                    "tags": [],
                }
        except requests.exceptions.SSLError as exc:
            logger.warning(f"URLhaus TLS verification error for {target_url}: {exc}")
            result = {
                "url": target_url,
                "query_status": "tls_verification_failed",
                "network_state": "TLS_ERROR",
                "is_malicious": False,
                "error": str(exc)
            }
        except Exception as exc:
            logger.warning(f"URLhaus connection error for {target_url}: {exc}")
            result = {
                "url": target_url,
                "query_status": "connection_error",
                "network_state": "NETWORK_ERROR",
                "is_malicious": False,
                "error": str(exc)
            }

        self.cache.set(cache_key, result)
        return result


class DoHReputationConnector:
    """DNS-over-HTTPS (DoH) threat resolution using Quad9 or Cloudflare Security DoH."""

    QUAD9_DOH = "https://dns.quad9.net/dns-query"
    CLOUDFLARE_DOH = "https://security.cloudflare-dns.com/dns-query"

    def __init__(self, cache: Optional[ThreatIntelCache] = None, timeout: float = 3.0):
        self.cache = cache or ThreatIntelCache()
        self.timeout = timeout

    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Query Quad9 threat-blocking DoH."""
        cache_key = f"doh:{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached

        clean_domain = domain.strip().lower().rstrip(".")
        headers = {"accept": "application/dns-json"}
        session, net_mode = get_enterprise_session()

        try:
            res = session.get(
                self.QUAD9_DOH,
                params={"name": clean_domain, "type": "A"},
                headers=headers,
                timeout=self.timeout,
            )
            if res.status_code == 200:
                data = res.json()
                status = data.get("Status", 0)
                answers = data.get("Answer", [])
                is_blocked = status == 3 or any(a.get("data") in ("0.0.0.0", "127.0.0.1") for a in answers)
                result = {
                    "domain": clean_domain,
                    "doh_provider": "quad9",
                    "network_state": net_mode,
                    "dns_status_code": status,
                    "is_blocked_by_threat_filter": is_blocked,
                    "answers": answers,
                }
            else:
                result = {
                    "domain": clean_domain,
                    "doh_provider": "quad9",
                    "network_state": "NETWORK_ERROR",
                    "dns_status_code": res.status_code,
                    "is_blocked_by_threat_filter": False,
                    "answers": [],
                }
        except requests.exceptions.SSLError as exc:
            result = {
                "domain": clean_domain,
                "doh_provider": "quad9",
                "network_state": "TLS_ERROR",
                "dns_status_code": -1,
                "is_blocked_by_threat_filter": False,
                "error": str(exc)
            }
        except Exception as exc:
            result = {
                "domain": clean_domain,
                "doh_provider": "quad9",
                "network_state": "NETWORK_ERROR",
                "dns_status_code": -1,
                "is_blocked_by_threat_filter": False,
                "error": str(exc)
            }

        self.cache.set(cache_key, result)
        return result


class AbuseIPDBConnector:
    """AbuseIPDB IP reputation connector with real API execution and explicit availability status."""

    API_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, cache: Optional[ThreatIntelCache] = None, timeout: float = 3.0):
        self.cache = cache or ThreatIntelCache()
        self.timeout = timeout
        self.network_guard = NetworkGuard()
        self.api_key = os.getenv("ABUSEIPDB_API_KEY") or os.getenv("ABUSE_IPDB_KEY")

    def check_ip(self, ip_address: str) -> Dict[str, Any]:
        cache_key = f"abuseipdb:{ip_address}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached

        is_allowed, reason, is_ssrf = self.network_guard.evaluate_destination(f"http://{ip_address}")
        if not is_allowed:
            result = {
                "ip": ip_address,
                "ipAddress": ip_address,
                "query_status": "blocked_by_network_guard",
                "network_state": "BLOCKED",
                "is_internal_or_restricted": True,
                "is_malicious": False,
                "abuse_confidence_score": 0,
                "source_classification": "LOCAL_GUARD",
                "detail": f"Destination blocked by NetworkGuard: {reason}"
            }
            self.cache.set(cache_key, result)
            return result

        # Check if API credentials are configured
        if not self.api_key:
            result = {
                "ip": ip_address,
                "ipAddress": ip_address,
                "query_status": "ABUSEIPDB_UNAVAILABLE",
                "network_state": "NOT_CONFIGURED",
                "is_configured": False,
                "is_internal_or_restricted": False,
                "is_malicious": False,
                "abuse_confidence_score": None,
                "source_classification": "UNAVAILABLE",
                "detail": "AbuseIPDB credentials not configured in environment (ABUSEIPDB_API_KEY)."
            }
            self.cache.set(cache_key, result)
            return result

        # Genuine API call with enterprise session
        session, net_mode = get_enterprise_session()
        try:
            response = session.get(
                self.API_URL,
                params={"ipAddress": ip_address, "maxAgeInDays": 90},
                headers={
                    "Key": self.api_key,
                    "Accept": "application/json",
                    "User-Agent": "AgenticEmailDefense-AbuseIPDB/1.0"
                },
                timeout=self.timeout
            )
            if response.status_code == 200:
                data = response.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                result = {
                    "ip": ip_address,
                    "ipAddress": ip_address,
                    "query_status": "ok",
                    "network_state": net_mode,
                    "is_configured": True,
                    "is_internal_or_restricted": False,
                    "is_malicious": score >= 50,
                    "abuse_confidence_score": score,
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "source_classification": "LIVE",
                }
            elif response.status_code in (401, 403):
                result = {
                    "ip": ip_address,
                    "ipAddress": ip_address,
                    "query_status": f"auth_error_{response.status_code}",
                    "network_state": "AUTH_ERROR",
                    "is_configured": True,
                    "is_malicious": False,
                    "abuse_confidence_score": None,
                    "source_classification": "AUTH_ERROR",
                    "detail": "Invalid or expired AbuseIPDB API key."
                }
            else:
                result = {
                    "ip": ip_address,
                    "ipAddress": ip_address,
                    "query_status": f"http_error_{response.status_code}",
                    "network_state": "NETWORK_ERROR",
                    "is_configured": True,
                    "is_malicious": False,
                    "abuse_confidence_score": None,
                    "source_classification": "NETWORK_ERROR",
                }
        except requests.exceptions.SSLError as exc:
            result = {
                "ip": ip_address,
                "ipAddress": ip_address,
                "query_status": "tls_error",
                "network_state": "TLS_ERROR",
                "is_configured": True,
                "is_malicious": False,
                "abuse_confidence_score": None,
                "source_classification": "TLS_ERROR",
                "detail": str(exc)
            }
        except Exception as exc:
            result = {
                "ip": ip_address,
                "ipAddress": ip_address,
                "query_status": "network_error",
                "network_state": "NETWORK_ERROR",
                "is_configured": True,
                "is_malicious": False,
                "abuse_confidence_score": None,
                "source_classification": "NETWORK_ERROR",
                "detail": str(exc)
            }

        self.cache.set(cache_key, result)
        return result

    def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        return self.check_ip(ip_address)


class FreeThreatIntelEngine:
    """Unified engine aggregating all free, open-source threat intelligence connectors."""

    def __init__(self):
        self.cache = ThreatIntelCache()
        self.urlhaus = URLhausConnector(cache=self.cache)
        self.doh = DoHReputationConnector(cache=self.cache)
        self.abuseipdb = AbuseIPDBConnector(cache=self.cache)

    def assess_indicator(self, indicator_type: str, indicator_value: str) -> Dict[str, Any]:
        """Assess an indicator (url, ip, domain) across all available free feeds."""
        if indicator_type == "url":
            url_res = self.urlhaus.query_url(indicator_value)
            parsed = urlparse(indicator_value)
            doh_res = self.doh.check_domain_reputation(parsed.hostname or "") if parsed.hostname else {}
            return {
                "indicator": indicator_value,
                "type": "url",
                "is_malicious": url_res.get("is_malicious", False) or doh_res.get("is_blocked_by_threat_filter", False),
                "urlhaus": url_res,
                "doh": doh_res,
            }
        elif indicator_type == "domain":
            doh_res = self.doh.check_domain_reputation(indicator_value)
            return {
                "indicator": indicator_value,
                "type": "domain",
                "is_malicious": doh_res.get("is_blocked_by_threat_filter", False),
                "doh": doh_res,
            }
        elif indicator_type == "ip":
            ip_res = self.abuseipdb.check_ip_reputation(indicator_value)
            return {
                "indicator": indicator_value,
                "type": "ip",
                "is_malicious": ip_res.get("is_malicious", False),
                "abuseipdb": ip_res,
            }
        return {
            "indicator": indicator_value,
            "type": indicator_type,
            "is_malicious": False,
            "details": "unsupported_indicator_type",
        }
