"""
NetworkGuard: Enforces strict outbound network boundary inside the Sandbox.
Uses URLNormalizer to decode obfuscated URIs, explicitly blocking RFC1918 private subnets,
localhost, cloud metadata endpoints, local file: URIs, data: URIs, and script URIs.
"""

import re
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

    NON_NETWORK_SCHEMES = {"file", "data", "javascript", "vbscript", "about", "search-ms", "ms-appinstaller"}

    def evaluate_destination(self, url_or_target: str) -> Tuple[bool, Optional[str], bool]:
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
                    return self._evaluate_host(norm.host)
                return False, f"Blocked: Local File System Access URI ({norm.normalized_url[:60]})", False
            elif norm.is_data_uri:
                return False, "Blocked: Inline Data URI Execution Payload", False
            elif norm.is_script_uri:
                return False, f"Blocked: Script URI Execution ({norm.scheme}:)", False
            elif norm.is_moniker_uri:
                if norm.is_unc_path:
                    return self._evaluate_host(norm.host)
                return False, f"Blocked: Moniker URI Execution ({norm.scheme}:)", False

        # 2. Network Schemes: Host evaluation
        host = norm.host
        if not host:
            # Never treat an empty hostname as safe!
            return False, f"Blocked: Missing or invalid network hostname ({norm.normalized_url[:40]})", False

        return self._evaluate_host(host)

    def _evaluate_host(self, host: str) -> Tuple[bool, Optional[str], bool]:
        host_low = host.lower().strip("[]")

        # 1. Check Cloud Metadata Endpoints
        if host_low in self.CLOUD_METADATA_HOSTS:
            return False, f"Blocked: Cloud Metadata Endpoint ({host_low})", True

        # 2. Check Localhost / Loopback
        if host_low in ["localhost", "127.0.0.1", "::1", "0.0.0.0"]:
            return False, f"Blocked: Localhost / Loopback destination ({host_low})", True

        # 3. Check IP address against RFC1918 & Link-local
        try:
            ip = ipaddress.ip_address(host_low)
            if ip.is_private:
                return False, f"Blocked: RFC1918 Private IP address ({host_low})", True
            if ip.is_loopback:
                return False, f"Blocked: Loopback IP ({host_low})", True
            if ip.is_link_local:
                return False, f"Blocked: Link-local IP ({host_low})", True
        except ValueError:
            # Domain name, check for suspicious internal domain suffixes
            if any(host_low.endswith(suf) for suf in [".internal", ".local", ".lan", ".corp", ".priv"]):
                return False, f"Blocked: Internal domain namespace ({host_low})", True

        # Allowed external destination
        return True, None, False
