"""
Agent Node: Exposure context.
Records the recipient domain as an asset. Platform fingerprinting only happens when real
fingerprint data (HTTP headers / HTML from the customer's own webmail) is supplied via state;
nothing is simulated, so no CVE is associated with an asset unless it was actually fingerprinted.
"""

import logging

from packages.schemas.python.models import SecurityState
from packages.attack_surface.src.attack_surface_engine import EmailAttackSurfaceEngine

logger = logging.getLogger("ExposureNode")


class ExposureNode:
    def __init__(self):
        self.surface_engine = EmailAttackSurfaceEngine()

    def execute(self, state: SecurityState) -> SecurityState:
        tenant_id = state.get("tenant_id", "default-tenant")
        email_dict = state.get("email_representation", {}) or {}
        recipients = email_dict.get("recipients") or []
        first = recipients[0].get("address", "") if recipients else ""
        if "@" not in first:
            state["asset_context"] = []
            return state
        domain = first.split("@")[-1]

        fingerprint = state.get("asset_fingerprint") or {}
        assets = self.surface_engine.discover_domain_assets(
            tenant_id=tenant_id,
            domain=domain,
            simulated_headers=fingerprint.get("http_headers"),
            simulated_html=fingerprint.get("html"),
        )
        state["asset_context"] = [a.model_dump() for a in assets]
        logger.info(f"ExposureNode recorded {len(assets)} asset(s) for {domain} (fingerprinted={bool(fingerprint)})")
        return state
