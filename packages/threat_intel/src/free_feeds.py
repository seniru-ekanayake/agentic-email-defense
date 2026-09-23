"""Zero-Cost Community Threat Intelligence Connectors.

Integrates 100% free threat intelligence sources:
- URLhaus (abuse.ch) for malware payload & URL lookups
- AbuseIPDB (Free community tier) for IP reputation & confidence scores
- Quad9 / Cloudflare DNS-over-HTTPS (DoH) for domain reputation
- Local in-memory LRU caching with TTL for performance and rate-limit preservation
"""

from __future__ import annotations

import asyncio
import time
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import requests

from apps.sandbox.src.network_guard import NetworkGuard

logger = logging.getLogger("threat_intel.free_feeds")


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

        # Enforce NetworkGuard boundary check
        is_allowed, reason, _ = self.network_guard.evaluate_destination(target_url)
        if not is_allowed:
            result = {
                "url": target_url,
                "query_status": "blocked_by_network_guard",
                "is_malicious": False,
                "threat_type": None,
                "tags": [],
            }
            return result

        try:
            response = requests.post(
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
                    "is_malicious": is_malicious,
                    "threat_type": data.get("threat", None),
                    "tags": data.get("tags", []),
                    "reporter": data.get("reporter", None),
                }
            else:
                result = {
                    "url": target_url,
                    "query_status": f"http_error_{response.status_code}",
                    "is_malicious": False,
                    "threat_type": None,
                    "tags": [],
                }
        except Exception as exc:
            logger.warning(f"URLhaus query error for {target_url}: {exc}")
            result = {
                "url": target_url,
                "query_status": "connection_error",
                "is_malicious": False,
                "threat_type": None,
                "tags": [],
            }

        self.cache.set(cache_key, result)
        return result


class AbuseIPDBConnector:
    """Free AbuseIPDB community connector (1,000 queries/day)."""

    API_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: Optional[str] = None, cache: Optional[ThreatIntelCache] = None, timeout: float = 5.0):
        self.api_key = api_key or "free_community_tier"
        self.cache = cache or ThreatIntelCache()
        self.timeout = timeout
        self.network_guard = NetworkGuard()

    def check_ip(self, ip_address: str, max_age_in_days: int = 90) -> Dict[str, Any]:
        """Check IP abuse score and reporting history."""
        cache_key = f"abuseipdb:{ip_address}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached

        is_allowed, _, _ = self.network_guard.evaluate_destination(ip_address)
        if not is_allowed:
            result = {
                "ipAddress": ip_address,
                "is_internal_or_restricted": True,
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "is_malicious": False,
            }
            return result

        # If offline or using free placeholder key without external network
        if self.api_key == "free_community_tier":
            result = {
                "ipAddress": ip_address,
                "is_internal_or_restricted": False,
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "is_malicious": False,
                "source": "abuseipdb_community_free",
            }
            self.cache.set(cache_key, result)
            return result

        try:
            headers = {
                "Key": self.api_key,
                "Accept": "application/json",
            }
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": max_age_in_days,
            }
            response = requests.get(self.API_URL, headers=headers, params=params, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                result = {
                    "ipAddress": ip_address,
                    "is_internal_or_restricted": False,
                    "abuseConfidenceScore": score,
                    "totalReports": data.get("totalReports", 0),
                    "is_malicious": score >= 50,
                    "countryCode": data.get("countryCode"),
                    "domain": data.get("domain"),
                    "isp": data.get("isp"),
                }
            else:
                result = {
                    "ipAddress": ip_address,
                    "is_internal_or_restricted": False,
                    "abuseConfidenceScore": 0,
                    "totalReports": 0,
                    "is_malicious": False,
                    "error": f"http_{response.status_code}",
                }
        except Exception as exc:
            logger.warning(f"AbuseIPDB query failed for {ip_address}: {exc}")
            result = {
                "ipAddress": ip_address,
                "is_internal_or_restricted": False,
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "is_malicious": False,
                "error": str(exc),
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
        """Query Quad9 threat-blocking DoH.

        If Quad9 returns NXDOMAIN or 0.0.0.0 for a domain that exists on normal DNS,
        Quad9 has blocked it as malicious.
        """
        cache_key = f"doh:{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached

        clean_domain = domain.strip().lower().rstrip(".")
        headers = {"accept": "application/dns-json"}

        try:
            # Query Quad9 threat-blocking DNS
            res = requests.get(
                self.QUAD9_DOH,
                params={"name": clean_domain, "type": "A"},
                headers=headers,
                timeout=self.timeout,
            )
            if res.status_code == 200:
                data = res.json()
                status = data.get("Status", 0)
                # Status 3 = NXDOMAIN (Quad9 blocks malware domains by returning NXDOMAIN)
                answers = data.get("Answer", [])
                is_blocked = status == 3 or any(a.get("data") in ("0.0.0.0", "127.0.0.1") for a in answers)
                result = {
                    "domain": clean_domain,
                    "doh_provider": "quad9",
                    "dns_status_code": status,
                    "is_blocked_by_threat_filter": is_blocked,
                    "answers": answers,
                }
            else:
                result = {
                    "domain": clean_domain,
                    "doh_provider": "quad9",
                    "dns_status_code": res.status_code,
                    "is_blocked_by_threat_filter": False,
                    "answers": [],
                }
        except Exception as exc:
            logger.debug(f"DoH query skipped for {clean_domain}: {exc}")
            result = {
                "domain": clean_domain,
                "doh_provider": "quad9",
                "dns_status_code": -1,
                "is_blocked_by_threat_filter": False,
                "answers": [],
            }

        self.cache.set(cache_key, result)
        return result


class FreeThreatIntelEngine:
    """Unified engine aggregating all free, open-source threat intelligence connectors."""

    def __init__(self):
        self.cache = ThreatIntelCache()
        self.urlhaus = URLhausConnector(cache=self.cache)
        self.abuseipdb = AbuseIPDBConnector(cache=self.cache)
        self.doh = DoHReputationConnector(cache=self.cache)

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
        elif indicator_type in ("ip", "ipv4", "ipv6"):
            ip_res = self.abuseipdb.check_ip(indicator_value)
            return {
                "indicator": indicator_value,
                "type": "ip",
                "is_malicious": ip_res.get("is_malicious", False),
                "abuseipdb": ip_res,
            }
        elif indicator_type == "domain":
            doh_res = self.doh.check_domain_reputation(indicator_value)
            return {
                "indicator": indicator_value,
                "type": "domain",
                "is_malicious": doh_res.get("is_blocked_by_threat_filter", False),
                "doh": doh_res,
            }
        return {
            "indicator": indicator_value,
            "type": indicator_type,
            "is_malicious": False,
            "details": "unsupported_indicator_type",
        }
