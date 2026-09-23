"""
Platform Fingerprint Adapters for Exchange/OWA, Zimbra, Google Workspace, and Generic/Roundcube.
"""

import re
from typing import Dict, Optional, Tuple
from packages.attack_surface.src.adapters.base_adapter import PlatformFingerprintAdapter


class ExchangeOwaAdapter(PlatformFingerprintAdapter):
    @property
    def platform_name(self) -> str:
        return "Microsoft Exchange / Outlook Web Access (OWA)"

    def fingerprint(
        self,
        headers: Dict[str, str],
        html_body: str,
        mx_host: Optional[str] = None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        # 1. Check HTTP/Email headers
        for k, v in headers.items():
            k_low = k.lower()
            v_low = v.lower()
            if "x-owa-version" in k_low or "x-calculatedbetarget" in k_low:
                version = headers.get(k)
                return True, self.platform_name, version
            if "server" in k_low and "microsoft-iis" in v_low:
                # Check for OWA paths in body or headers
                if "/owa" in html_body.lower() or "/ecp" in html_body.lower():
                    return True, self.platform_name, "Exchange 2016/2019"

        # 2. Check HTML / Body features
        if "/owa/auth/logon.aspx" in html_body or "outlook web app" in html_body.lower() or "owa/" in html_body.lower():
            version_match = re.search(r"owa/auth/([0-9\.]+)", html_body, re.IGNORECASE)
            version = version_match.group(1) if version_match else "15.1.x"
            return True, self.platform_name, version

        # 3. Check MX Host
        if mx_host and ("mail.protection.outlook.com" in mx_host.lower() or "exchange" in mx_host.lower()):
            return True, "Microsoft 365 / Exchange Online", "Cloud"

        return False, None, None


class ZimbraAdapter(PlatformFingerprintAdapter):
    @property
    def platform_name(self) -> str:
        return "Zimbra Collaboration Suite (ZCS)"

    def fingerprint(
        self,
        headers: Dict[str, str],
        html_body: str,
        mx_host: Optional[str] = None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        # 1. Check Headers
        for k, v in headers.items():
            if "zimbra" in k.lower() or "zimbra" in v.lower():
                return True, self.platform_name, "8.8.x / 9.0.x"

        # 2. Check HTML Body / Webmail paths
        if "/zimbra/" in html_body or "zimbraWebClient" in html_body or "zimbra_skin" in html_body:
            version_match = re.search(r"zimbra\s*(?:version|release)?\s*([0-9\.]+)", html_body, re.IGNORECASE)
            version = version_match.group(1) if version_match else "8.8.15"
            return True, self.platform_name, version

        if mx_host and "zimbra" in mx_host.lower():
            return True, self.platform_name, "Unknown"

        return False, None, None


class GoogleWorkspaceAdapter(PlatformFingerprintAdapter):
    @property
    def platform_name(self) -> str:
        return "Google Workspace / Gmail"

    def fingerprint(
        self,
        headers: Dict[str, str],
        html_body: str,
        mx_host: Optional[str] = None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        if mx_host and ("aspmx.l.google.com" in mx_host.lower() or "googlemail.com" in mx_host.lower()):
            return True, self.platform_name, "SaaS"

        for k, v in headers.items():
            if "google.com" in v.lower() and "received" in k.lower():
                return True, self.platform_name, "SaaS"

        return False, None, None


class GenericRoundcubeAdapter(PlatformFingerprintAdapter):
    @property
    def platform_name(self) -> str:
        return "Roundcube Webmail"

    def fingerprint(
        self,
        headers: Dict[str, str],
        html_body: str,
        mx_host: Optional[str] = None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        if "roundcube" in html_body.lower() or "rcmail" in html_body:
            version_match = re.search(r"roundcube\s*webmail\s*([0-9\.]+)", html_body, re.IGNORECASE)
            version = version_match.group(1) if version_match else "1.4.x"
            return True, self.platform_name, version

        return False, None, None
