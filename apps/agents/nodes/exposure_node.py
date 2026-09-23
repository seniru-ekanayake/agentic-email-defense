"""
Agent Node 4: Exposure & Attack Surface Correlation Node.
Correlates identified vulnerability hypotheses with actual customer assets and exposure telemetry.
"""

import logging
from typing import Dict, Any, List

from packages.schemas.python.models import SecurityState
from packages.attack_surface.src.attack_surface_engine import EmailAttackSurfaceEngine
from packages.attack_surface.src.models import AssetState

logger = logging.getLogger("ExposureNode")


class ExposureNode:
    def __init__(self):
        self.surface_engine = EmailAttackSurfaceEngine()

    def execute(self, state: SecurityState) -> SecurityState:
        tenant_id = state.get("tenant_id", "default-tenant")
        logger.info(f"ExposureNode executing for tenant: {tenant_id}")

        email_dict = state.get("email_representation", {})
        recipient_domain = "enterprise-corp.internal"
        if email_dict.get("recipients"):
            first_rec = email_dict["recipients"][0]["address"]
            if "@" in first_rec:
                recipient_domain = first_rec.split("@")[-1]

        # Discover domain assets
        simulated_headers = {"X-OWA-Version": "15.1.2507.17", "Server": "Microsoft-IIS/10.0"}
        assets = self.surface_engine.discover_domain_assets(
            tenant_id=tenant_id,
            domain=recipient_domain,
            simulated_headers=simulated_headers
        )

        state["asset_context"] = [a.model_dump() for a in assets]

        # Correlate asset exposure with active email attack
        if assets:
            target_asset = assets[0]
            # Update state machine to ATTACK_OBSERVED if exploit indicators exist
            if email_dict.get("exploit_indicators"):
                if AssetState.ATTACK_OBSERVED.value not in [s if isinstance(s, str) else s.value for s in target_asset.states]:
                    target_asset.states.append(AssetState.ATTACK_OBSERVED)

            state["evidence"].append({
                "stage": "EXPOSURE_CORRELATION",
                "asset_host": target_asset.host,
                "product": target_asset.product,
                "version": target_asset.version,
                "is_exposed": target_asset.is_internet_facing,
                "states": [s if isinstance(s, str) else s.value for s in target_asset.states]
            })

        logger.info(f"ExposureNode completed. Correlated {len(assets)} exposed asset(s).")
        return state
