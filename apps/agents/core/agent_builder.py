"""
Tenant-scoped planner settings.

These are the only configuration knobs the investigation pipeline consumes: which planner to
use and how Rule/LLM disagreements are arbitrated. Settings are validated and persisted in
DurableStorage per tenant.
"""

from typing import Literal

from pydantic import BaseModel, Field

from apps.agents.core.durable_storage import DurableStorage

SETTINGS_KEY = "planner_settings"


class PlannerSettings(BaseModel):
    planner_mode: Literal["RULE", "LLM", "HYBRID", "AUTO"] = "HYBRID"
    hybrid_arbitration_policy: Literal[
        "RULE_FIRST", "LLM_FIRST", "CONSENSUS_REQUIRED", "EVIDENCE_WEIGHTED", "INFORMATION_GAIN_WEIGHTED", "SAFETY_FIRST"
    ] = "RULE_FIRST"
    max_llm_calls: int = Field(default=10, ge=0, le=50)

    model_config = {"extra": "forbid"}


def get_planner_settings(tenant_id: str) -> PlannerSettings:
    stored = DurableStorage.get_instance().get_setting(tenant_id, SETTINGS_KEY)
    return PlannerSettings(**stored) if stored else PlannerSettings()


def save_planner_settings(tenant_id: str, settings: PlannerSettings) -> PlannerSettings:
    DurableStorage.get_instance().set_setting(tenant_id, SETTINGS_KEY, settings.model_dump())
    return settings
