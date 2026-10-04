"""
Core Identity & Authentication Abstraction for FishingMails.
Provides fail-closed production-grade AuthenticatedPrincipal extraction,
strict JWT validation, algorithm enforcement, and server-side tenant authority.
"""

import os
import time
import logging
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import jwt
from fastapi import Request, HTTPException

logger = logging.getLogger("SecurityPrincipal")

JWT_ALGORITHM = "HS256"
INSECURE_DEV_SECRETS = {
    "",
    "dev-secret",
    "secret",
    "change-me",
    "test",
    "12345678",
    "fishingmails-dev-insecure-test-secret-change-in-production"
}
DEV_FALLBACK_SECRET = "fishingmails-dev-test-secret-minimum-32-chars-long-for-local-testing"


def get_environment() -> str:
    """
    Returns the normalized operating environment:
    'production', 'staging', 'development', or 'test'.
    Defaults deterministically to 'production' (fail-closed) if unset.
    """
    raw = os.environ.get("FISHINGMAILS_ENV", "").strip().lower()
    if raw in ("production", "staging", "development", "test"):
        return raw

    # Check ProductionManager fallback if available
    try:
        from apps.agents.core.production_manager import ProductionManager, PlatformMode
        pm = ProductionManager.get_instance()
        if pm.current_mode == PlatformMode.DEVELOPMENT:
            return "development"
        elif pm.current_mode == PlatformMode.TEST:
            return "test"
    except Exception:
        pass

    return "production"


def is_production_mode() -> bool:
    """Returns True if running in production or staging mode."""
    return get_environment() in ("production", "staging")


def is_local_auth_fallback_enabled() -> bool:
    """
    Determines if local unauthenticated fallback to 'local_analyst' is permitted.
    
    STRICT SECURITY INVARIANTS:
    1. NEVER permitted in PRODUCTION or STAGING mode under any circumstances.
    2. If FISHINGMAILS_ALLOW_LOCAL_AUTH_FALLBACK is set in production/staging,
       raises RuntimeError (fails closed at boot/call time).
    3. In DEVELOPMENT or TEST mode, fallback is disabled by default and requires
       explicit FISHINGMAILS_ALLOW_LOCAL_AUTH_FALLBACK='true'.
    """
    raw_fallback = os.environ.get("FISHINGMAILS_ALLOW_LOCAL_AUTH_FALLBACK", "").strip().lower()
    fallback_requested = raw_fallback in ("true", "1", "yes")

    if is_production_mode():
        if fallback_requested:
            raise RuntimeError(
                f"FATAL SECURITY CONFIGURATION ERROR: FISHINGMAILS_ALLOW_LOCAL_AUTH_FALLBACK is enabled, "
                f"but operating environment is '{get_environment()}'. Local authentication fallback "
                f"is strictly forbidden in production and staging environments. Failing closed."
            )
        return False

    return fallback_requested


def get_jwt_secret_key() -> str:
    """
    Retrieves and validates the JWT signing secret.
    
    In PRODUCTION / STAGING:
    - Must be explicitly set via FISHINGMAILS_AUTH_SECRET.
    - Must NOT be empty or an insecure default.
    - Must be at least 32 characters long.
    - If missing or insecure, raises RuntimeError (fail closed).
    
    In DEVELOPMENT / TEST:
    - Defaults to a development testing secret if unset.
    """
    secret = os.environ.get("FISHINGMAILS_AUTH_SECRET", "").strip()

    if is_production_mode():
        if not secret or secret in INSECURE_DEV_SECRETS or len(secret) < 32:
            raise RuntimeError(
                f"FATAL SECURITY CONFIGURATION ERROR: FISHINGMAILS_AUTH_SECRET must be explicitly set "
                f"to a cryptographically secure key of at least 32 characters in '{get_environment()}' mode. "
                f"Refusing to operate with insecure or missing authentication secret."
            )
        return secret

    if not secret:
        return DEV_FALLBACK_SECRET
    return secret


class AuthenticatedPrincipal(BaseModel):
    subject_id: str
    tenant_id: str
    roles: List[str] = Field(default_factory=lambda: ["SOC_ANALYST"])
    token_id: Optional[str] = None
    is_service: bool = False

    def has_role(self, required_role: str) -> bool:
        return required_role in self.roles or "ADMIN" in self.roles or "SOC_ADMIN" in self.roles


def create_principal_token(
    subject_id: str,
    tenant_id: str,
    roles: Optional[List[str]] = None,
    expires_in_seconds: int = 86400,
    secret_key: Optional[str] = None
) -> str:
    """
    Generates a cryptographically signed JWT token for an authenticated principal.
    Strictly signs using HS256 algorithm with explicit sub, tenant_id, iat, and exp.
    """
    now = time.time()
    payload = {
        "sub": subject_id,
        "tenant_id": tenant_id,
        "roles": roles or ["SOC_ANALYST"],
        "iat": now,
        "exp": now + expires_in_seconds
    }
    key = secret_key or get_jwt_secret_key()
    return jwt.encode(payload, key, algorithm=JWT_ALGORITHM)


def get_authenticated_principal(request: Request) -> AuthenticatedPrincipal:
    """
    Extracts and cryptographically verifies the caller's identity.
    
    FAIL-CLOSED ENFORCEMENT:
    1. No Authorization header:
       - If development fallback is explicitly enabled, logs security audit and resolves to local_analyst.
       - In production, or if fallback is not explicitly enabled, raises HTTP 401 Unauthorized.
    2. Malformed Authorization header (not starting with 'Bearer '):
       - Raises HTTP 401 Unauthorized.
    3. Empty token:
       - Raises HTTP 401 Unauthorized.
    4. JWT verification:
       - Mandatory signature verification.
       - Algorithm strictly pinned to HS256 (prevents algorithm confusion attacks like 'none' or 'RS256').
       - Mandatory expiration check (exp).
       - Mandatory subject claim (sub).
       - Mandatory tenant claim (tenant_id).
       - Any verification failure raises HTTP 401 Unauthorized.
    5. Roles parsed strictly from verified claims.
    """
    auth_header = request.headers.get("Authorization")

    if not auth_header:
        if is_local_auth_fallback_enabled():
            logger.warning(
                "[SECURITY AUDIT] Unauthenticated request permitted via EXPLICIT development fallback. "
                "Identity: 'local_analyst' bound to 'tenant-enterprise-prod'."
            )
            return AuthenticatedPrincipal(
                subject_id="local_analyst",
                tenant_id=os.environ.get("DEFAULT_TENANT_ID", "tenant-enterprise-prod"),
                roles=["SOC_ANALYST", "INCIDENT_RESPONDER"]
            )
        raise HTTPException(
            status_code=401,
            detail="Authentication required: Missing Authorization header."
        )

    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authentication failed: Authorization header must use 'Bearer <token>' scheme."
        )

    raw_token = auth_header.split(" ", 1)[1].strip()
    if not raw_token:
        raise HTTPException(
            status_code=401,
            detail="Authentication failed: Empty Bearer token."
        )

    secret = get_jwt_secret_key()
    try:
        payload = jwt.decode(
            raw_token,
            secret,
            algorithms=[JWT_ALGORITHM],
            options={
                "require": ["exp", "sub", "tenant_id"],
                "verify_exp": True,
                "verify_signature": True,
            }
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Authentication failed: JWT token has expired."
        )
    except jwt.InvalidSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Authentication failed: Invalid JWT signature."
        )
    except jwt.InvalidAlgorithmError:
        raise HTTPException(
            status_code=401,
            detail="Authentication failed: Unsupported or forbidden JWT algorithm."
        )
    except jwt.MissingRequiredClaimError as err:
        raise HTTPException(
            status_code=401,
            detail=f"Authentication failed: Missing required claim ({err})."
        )
    except jwt.DecodeError:
        raise HTTPException(
            status_code=401,
            detail="Authentication failed: Malformed or unparseable JWT."
        )
    except jwt.PyJWTError as err:
        logger.warning(f"JWT verification failed: {err}")
        raise HTTPException(
            status_code=401,
            detail=f"Authentication failed: {str(err)}"
        )

    sub = payload.get("sub")
    tenant_id = payload.get("tenant_id")
    roles = payload.get("roles", ["SOC_ANALYST"])
    if not isinstance(roles, list):
        roles = [str(roles)]

    return AuthenticatedPrincipal(
        subject_id=sub,
        tenant_id=tenant_id,
        roles=roles
    )


def resolve_authorized_tenant(
    request: Request,
    principal: AuthenticatedPrincipal
) -> str:
    """
    Enforces server-side tenant authority:
    The authorized tenant is strictly derived from principal.tenant_id.
    Client-supplied X-Tenant-ID / tenant_id query parameters are treated ONLY
    as a consistency check. If the client requests a foreign tenant, access is DENIED (HTTP 403).
    """
    authorized_tenant_id = principal.tenant_id

    requested_tenant = (
        request.headers.get("X-Tenant-ID") or
        request.query_params.get("tenant_id")
    )

    if requested_tenant and requested_tenant != authorized_tenant_id:
        logger.warning(
            f"Tenant spoofing attempt blocked: Principal '{principal.subject_id}' "
            f"(Tenant: '{authorized_tenant_id}') requested unauthorized Tenant '{requested_tenant}'."
        )
        raise HTTPException(
            status_code=403,
            detail=f"Access Denied: Authenticated identity '{principal.subject_id}' belongs to tenant '{authorized_tenant_id}', not '{requested_tenant}'."
        )

    return authorized_tenant_id
