"""
Production & Environment Separation Manager for FishingMails.
Enforces strict boundaries between PRODUCTION, DEVELOPMENT, DEMO, and TEST modes.
In PRODUCTION mode:
- ZERO preloaded incidents
- ZERO mocks
- ZERO static attack chains
- ZERO synthetic fixtures
All data must strictly originate from actual ingested emails and live tools.
"""

import os
from enum import Enum
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class PlatformMode(str, Enum):
    PRODUCTION = "PRODUCTION"
    DEVELOPMENT = "DEVELOPMENT"
    DEMO = "DEMO"
    TEST = "TEST"


class ProductionManager:
    """Singleton managing operating mode and enforcing production purity rules."""
    _instance: Optional["ProductionManager"] = None

    def __init__(self, initial_mode: PlatformMode = PlatformMode.PRODUCTION):
        self._current_mode: PlatformMode = initial_mode

    @classmethod
    def get_instance(cls) -> "ProductionManager":
        if cls._instance is None:
            env = (os.environ.get("FISHINGMAILS_ENV") or os.environ.get("ENVIRONMENT") or "production").strip().lower()
            mode = {"development": PlatformMode.DEVELOPMENT, "test": PlatformMode.TEST}.get(env, PlatformMode.PRODUCTION)
            cls._instance = ProductionManager(mode)
        return cls._instance

    @property
    def current_mode(self) -> PlatformMode:
        return self._current_mode

    def set_mode(self, mode: PlatformMode):
        self._current_mode = mode

    def is_production(self) -> bool:
        return self._current_mode == PlatformMode.PRODUCTION

    def allows_fixtures(self) -> bool:
        return self._current_mode in [PlatformMode.DEMO, PlatformMode.TEST]

    def allows_mocks(self) -> bool:
        return self._current_mode in [PlatformMode.DEVELOPMENT, PlatformMode.TEST]

    def get_status_summary(self) -> Dict[str, Any]:
        return {
            "mode": self._current_mode.value,
            "is_production": self.is_production(),
            "allows_fixtures": self.allows_fixtures(),
            "allows_mocks": self.allows_mocks(),
            "mocks_active": False if self.is_production() else True,
            "fixtures_active": False if self.is_production() else True,
            "badge_color": "#16945b" if self.is_production() else "#b7791f",
            "warning": None if self.is_production() else "DEMO/DEV FIXTURES ENABLED: Non-production synthetic samples permitted."
        }
