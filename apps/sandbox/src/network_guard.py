"""
NetworkGuard: Enforces strict outbound network boundary inside the Sandbox.
Uses URLNormalizer to decode obfuscated URIs, explicitly blocking RFC1918 private subnets,
localhost, cloud metadata endpoints, local file: URIs, data: URIs, and script URIs.
"""

import re
import socket
import urllib.parse
import ipaddress
from typing import Tuple, Optional
from packages.email_parser.src.url_normalizer import URLNormalizer, NormalizedUrl


class NetworkGuard:
    """
    Evaluates requested URLs and network destinations against security boundaries.
    """

    CLOUD_METADATA_HOSTS = [
        "169.254.169.254",
        "metadata.google.internal",
        "instance-data",
        "100.100.100.200"  # Alibaba cloud metadata
    ]

    INTERNAL_SUFFIXES = (".internal", ".local", ".lan", ".corp", ".priv", ".home.arpa")

    NON_NETWORK_SCHEMES = {"file", "data", "javascript", "vbscript", "about", "search-ms", "ms-appinstaller"}

    def evaluate_destination(self, url_or_target: str, resolve: bool = False) -> Tuple[bool, Optional[str], bool]:
        """
        Evaluates a URL, IP, UNC, or non-network URI target.
        Returns: (is_allowed, block_reason, is_ssrf_attempt)
        """
        if not url_or_target:
            return False, "Blocked: Empty destination URI", False

        # Normalize URL/URI using URLNormalizer
        norm = URLNormalizer.normalize(url_or_target)

        # 1. Non-Network Schemes (file:, data:, javascript:, vbscript:, about:)
        if norm.scheme in self.NON_NETWORK_SCHEMES or norm.is_local_file_url or norm.is_data_uri or norm.is_script_uri:
            if norm.is_local_file_url or norm.scheme == "file":
                if norm.is_unc_path:
                    # UNC paths may trigger outbound SMB/NTLM relay
                    return self._evaluate_host(norm.host, resolve)
                return False, f"Blocked: Local File System Access URI ({norm.normalized_url[:60]})", False
            elif norm.is_data_uri:
                return False, "Blocked: Inline Data URI Execution Payload", False
            elif norm.is_script_uri:
                return False, f"Blocked: Script URI Execution ({norm.scheme}:)", False
            elif norm.is_moniker_uri:
                if norm.is_unc_path:
                    return self._evaluate_host(norm.host, resolve)
                return False, f"Blocked: Moniker URI Execution ({norm.scheme}:)", False

        # 2. Network Schemes: Host evaluation
        host = norm.host
        if not host:
            # Never treat an empty hostname as safe!
            return False, f"Blocked: Missing or invalid network hostname ({norm.normalized_url[:40]})", False

        return self._evaluate_host(host, resolve)

    def _evaluate_host(self, host: str, resolve: bool = False) -> Tuple[bool, Optional[str], bool]:
        host_low = (host or "").lower().strip("[]").rstrip(".")
        if not host_low:
            return False, "Blocked: Empty hostname", False

        if host_low in self.CLOUD_METADATA_HOSTS:
            return False, f"Blocked: Cloud Metadata Endpoint ({host_low})", True
        if host_low == "localhost" or host_low.endswith(".localhost"):
            return False, f"Blocked: Localhost / Loopback destination ({host_low})", True
        if any(host_low.endswith(suf) for suf in self.INTERNAL_SUFFIXES):
            return False, f"Blocked: Internal domain namespace ({host_low})", True

        literal = self._parse_ip_literal(host_low)
        if literal is not None:
            if not literal.is_global:
                return False, f"Blocked: {self._describe(literal)} ({host_low} -> {literal})", True
            return True, None, False

        if resolve:
            try:
                infos = socket.getaddrinfo(host_low, None)
            except (socket.gaierror, UnicodeError):
                return False, f"Blocked: Hostname does not resolve ({host_low})", False
            for info in infos:
                addr = ipaddress.ip_address(info[4][0].split("%")[0])
                if not addr.is_global:
                    return False, f"Blocked: {host_low} resolves to {self._describe(addr)} {addr}", True
        return True, None, False

    @staticmethod
    def _describe(ip) -> str:
        if ip.is_loopback:
            return "Loopback address"
        if ip.is_link_local:
            return "Link-local address"
        if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"):
            return "Carrier-grade NAT address"
        if ip.is_private:
            return "RFC1918 Private IP address" if isinstance(ip, ipaddress.IPv4Address) else "Private IPv6 address"
        return "Non-public IP address"

    @staticmethod
    def _parse_ip_literal(host: str) -> Optional[ipaddress._BaseAddress]:
        """Parses IPv4/IPv6 literals, including legacy forms (127.1, 0x7f000001, 2130706433, 0177.0.0.1)."""
        try:
            ip = ipaddress.ip_address(host)
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                return ip.ipv4_mapped
            return ip
        except ValueError:
            pass
        if re.fullmatch(r"[0-9a-fx.]+", host) and not re.search(r"[g-wyz]", host):
            try:
                return ipaddress.ip_address(socket.inet_aton(host))
            except OSError:
                return None
        return None
