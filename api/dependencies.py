"""
FastAPI dependency injection for authentication.

Provides:
  - get_current_user: Requires valid JWT, raises 401 if missing/invalid.
    When AUTH_ENABLED is false, returns a default anonymous user.
  - optional_auth: Does not require JWT, but fills user info if token present.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import Depends, HTTPException, Request

from api import database as db
from api.auth import AUTH_ENABLED, _ensure_default_admin, decode_token

logger = logging.getLogger(__name__)

# Default anonymous user used when auth is disabled
_ANONYMOUS_USER: dict[str, Any] = {
    "id": 0,
    "username": "anonymous",
    "is_admin": False,
}


async def get_current_user(request: Request) -> dict[str, Any]:
    """
    FastAPI dependency that extracts and validates the JWT from the
    Authorization header.

    Behavior:
      - If AUTH_ENABLED is false: returns an anonymous user dict (no auth required).
      - If AUTH_ENABLED is true: requires a valid Bearer token in the
        Authorization header.  Raises HTTPException(401) on failure.
    """
    if not AUTH_ENABLED:
        return _ANONYMOUS_USER.copy()

    _ensure_default_admin()

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_header[7:]
    payload = decode_token(token)

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")

    user_id = int(payload["sub"])
    user = db.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    return user


async def optional_auth(request: Request) -> Optional[dict[str, Any]]:
    """
    FastAPI dependency that does NOT require authentication but fills in
    user info if a valid token is present.

    Returns:
      - The user dict if a valid Bearer token is found.
      - None if no token is provided or the token is invalid.
      - An anonymous user dict if AUTH_ENABLED is false and no token is given.
    """
    if not AUTH_ENABLED:
        return _ANONYMOUS_USER.copy()

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header[7:]
    try:
        payload = decode_token(token)
    except HTTPException:
        return None

    if payload.get("type") != "access":
        return None

    user_id = int(payload["sub"])
    user = db.get_user_by_id(user_id)
    if user is None:
        return None

    return user
