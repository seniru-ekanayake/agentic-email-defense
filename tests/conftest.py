import os
import sys

# Ensure repository root is on Python sys.path
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

# Configure default test environment invariants for pytest runs
os.environ.setdefault("FISHINGMAILS_ENV", "test")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("FISHINGMAILS_AUTH_SECRET", "fishingmails-prod-enterprise-agentic-jwt-signing-key-32bytes-min")
os.environ.setdefault("FISHINGMAILS_APPROVAL_HMAC_SECRET", "test-hmac-secret-key-that-is-long-enough-32bytes")

# Ensure ProductionManager is initialized in TEST mode for test discovery
try:
    from apps.agents.core.production_manager import ProductionManager, PlatformMode
    ProductionManager.get_instance().set_mode(PlatformMode.TEST)
except Exception:
    pass
