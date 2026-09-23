"""
NetworkGuard: Enforces strict outbound network boundary inside the Sandbox.
Blocks RFC1918 private subnets, localhost, and cloud metadata endpoints to prevent SSRF and internal scanning.
"""

import re
import urllib.parse
import ipaddress
from typing import Tuple, Optional


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

    def evaluate_destination(self, url_or_target: str) -> Tuple[bool, Optional[str], bool]:
        """
        Evaluates a URL or IP/UNC target.
        Returns: (is_allowed, block_reason, is_ssrf_attempt)
        """
        if not url_or_target:
            return False, "Empty destination", False

        # Check UNC / SMB paths
        if url_or_target.startswith("\\\\") or url_or_target.startswith("//"):
            clean_host = url_or_target.lstrip("\\/").split("\\")[0].split("/")[0]
            return self._evaluate_host(clean_host)

        # Parse standard URL
        try:
            parsed = urllib.parse.urlparse(url_or_target)
            host = parsed.hostname or url_or_target.split("/")[0]
            if ":" in host:
                host = host.split(":")[0]
            return self._evaluate_host(host)
        except Exception:
            return False, "Malformed destination URL", False

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
