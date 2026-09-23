"""
Base Abstract Fingerprint Adapter for Email and Webmail Systems.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple


class PlatformFingerprintAdapter(ABC):
    @property
    @abstractmethod
    def platform_name(self) -> str:
        """Name of the platform."""
        pass

    @abstractmethod
    def fingerprint(
        self,
        headers: Dict[str, str],
        html_body: str,
        mx_host: Optional[str] = None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Returns (is_match, product_name, detected_version).
        """
        pass
