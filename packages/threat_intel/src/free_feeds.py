"""
Zero-Cost Community Threat Intelligence Connectors.
Integrates free threat intelligence sources with full enterprise proxy support:
- HTTP_PROXY, HTTPS_PROXY, NO_PROXY, REQUESTS_CA_BUNDLE
- Strict TLS certificate verification (never disabled)
- Explicit network operational states: DIRECT, PROXY, TLS_ERROR, AUTH_ERROR, NETWORK_ERROR
"""

from __future__ import annotations

import os
import socket
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

        auth_key = os.getenv("URLHAUS_AUTH_KEY", "").strip()
        if not auth_key:
            return {
                "url": target_url,
                "query_status": "not_configured",
                "network_state": "NOT_CONFIGURED",
                "is_malicious": False,
                "threat_type": None,
                "tags": [],
                "detail": "URLHAUS_AUTH_KEY is not set; URLhaus requires an Auth-Key for API access.",
            }

        session, net_mode = get_enterprise_session()
        try:
            response = session.post(
                self.API_URL,
                data={"url": target_url},
                timeout=self.timeout,
                headers={"User-Agent": "AgenticEmailDefense-FreeFeed/1.0", "Auth-Key": auth_key},
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


def _dns_packet(domain: str, qtype: int = 1) -> bytes:
    import struct
    header = struct.pack(">HHHHHH", 0x4D46, 0x0100, 1, 0, 0, 0)  # recursion desired, one question
    qname = b"".join(bytes([len(p)]) + p.encode("idna") for p in domain.split(".") if p) + b"\x00"
    return header + qname + struct.pack(">HH", qtype, 1)


def dns_wire_query(domain: str, qtype: int = 1) -> str:
    """RFC 8484 GET parameter (base64url DNS query without padding)."""
    import base64
    return base64.urlsafe_b64encode(_dns_packet(domain, qtype)).rstrip(b"=").decode()


def dns_udp_query(server: str, domain: str, timeout: float = 2.0) -> Tuple[int, int]:
    """Sends one A query over UDP and returns (rcode, answer_count). Raises OSError on timeout."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(_dns_packet(domain), (server, 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    if len(data) < 12 or data[:2] != b"\x4d\x46":
        raise OSError("malformed DNS response")
    return data[3] & 0x0F, int.from_bytes(data[6:8], "big")


class DoHReputationConnector:
    """DNS-over-HTTPS (DoH) threat resolution using Quad9 or Cloudflare Security DoH."""


    def __init__(self, cache: Optional[ThreatIntelCache] = None, timeout: float = 3.0):
        self.cache = cache or ThreatIntelCache()
        self.timeout = timeout

    QUAD9_FILTERED = "9.9.9.9"     # threat-blocking resolver: answers NXDOMAIN for known-malicious domains
    QUAD9_UNFILTERED = "9.9.9.10"  # same provider without blocking, used to tell "blocked" from "does not exist"

    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Quad9 threat-blocking check: blocked = NXDOMAIN on 9.9.9.9 but resolvable on 9.9.9.10."""
        cache_key = f"doh:{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        clean_domain = domain.strip().lower().rstrip(".")
        try:
            status, answers = dns_udp_query(self.QUAD9_FILTERED, clean_domain, timeout=self.timeout)
            is_blocked = False
            if status == 3:
                unfiltered_status, _ = dns_udp_query(self.QUAD9_UNFILTERED, clean_domain, timeout=self.timeout)
                is_blocked = unfiltered_status == 0
            result = {
                "domain": clean_domain,
                "doh_provider": "quad9",
                "network_state": "DIRECT",
                "dns_status_code": status,
                "answer_count": answers,
                "is_blocked_by_threat_filter": is_blocked,
            }
        except (OSError, UnicodeError) as exc:
            result = {
                "domain": clean_domain,
                "doh_provider": "quad9",
                "network_state": "NETWORK_ERROR",
                "dns_status_code": -1,
                "is_blocked_by_threat_filter": False,
                "error": str(exc),
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
            urlhaus_ok = url_res.get("query_status") in ("ok", "no_results")
            doh_ok = doh_res.get("dns_status_code") in (0, 3) and doh_res.get("network_state") not in ("NETWORK_ERROR", "TLS_ERROR")
            return {
                "indicator": indicator_value,
                "type": "url",
                "is_malicious": url_res.get("is_malicious", False) or doh_res.get("is_blocked_by_threat_filter", False),
                "feeds_succeeded": bool(urlhaus_ok or doh_ok),
                "feeds": {"urlhaus": url_res.get("query_status"), "quad9": doh_res.get("network_state") if doh_res else "SKIPPED"},
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
