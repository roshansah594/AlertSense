"""AlertSense Authentication and Role-Based Access Control (RBAC).

Provides secure token-based authentication and role-based authorization:
- Supports Bearer token and X-API-Key headers.
- Enforces role separation: 'admin' vs 'user' / 'analyst'.
- Reads credentials securely from environment variables.
- Protects administrative endpoints like platform reset.
"""

from __future__ import annotations

import hmac
import logging
import os
from typing import Optional
from pydantic import BaseModel
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger(__name__)

# Security bearer scheme for OpenAPI documentation (optional in header)
bearer_scheme = HTTPBearer(auto_error=False)


class User(BaseModel):
    """Authenticated user context."""
    username: str
    role: str  # "admin" | "user"


def get_configured_keys() -> tuple[str, str]:
    """Retrieve API keys from environment with secure development defaults.
    
    In production (ENVIRONMENT=production), keys must be explicitly configured.
    """
    env = os.getenv("ENVIRONMENT", "development").lower().strip()
    admin_key = os.getenv("ADMIN_API_KEY", "").strip()
    user_key = os.getenv("USER_API_KEY", "").strip()

    if not admin_key:
        if env == "production":
            logger.critical("ADMIN_API_KEY is not configured in production environment!")
        else:
            admin_key = "alertsense-admin-dev-key"

    if not user_key:
        if env == "production":
            logger.critical("USER_API_KEY is not configured in production environment!")
        else:
            user_key = "alertsense-user-dev-key"

    return admin_key, user_key


def authenticate_token(token: str) -> Optional[User]:
    """Validate a token against configured roles using constant-time comparison."""
    if not token:
        return None

    admin_key, user_key = get_configured_keys()

    token_bytes = token.strip().encode("utf-8")
    
    if admin_key and hmac.compare_digest(token_bytes, admin_key.encode("utf-8")):
        return User(username="admin", role="admin")

    if user_key and hmac.compare_digest(token_bytes, user_key.encode("utf-8")):
        return User(username="analyst", role="user")

    return None


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key")
) -> User:
    """Dependency that verifies authentication and returns the current user.
    
    Accepts token via Authorization: Bearer <token> or X-API-Key: <token>.
    Raises HTTP 401 if token is missing or invalid.
    """
    token = None
    if credentials and credentials.credentials:
        token = credentials.credentials
    elif x_api_key:
        token = x_api_key

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide a valid Bearer token or X-API-Key header.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user = authenticate_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Dependency that enforces administrator role requirement.
    
    Raises HTTP 403 if the authenticated user is not an administrator.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Administrator privileges required for this operation."
        )
    return current_user
