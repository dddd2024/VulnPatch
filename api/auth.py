"""
JWT-based authentication module for VulnPatch.

Provides:
  - Password hashing (bcrypt with hashlib/sha256 fallback)
  - JWT token generation and validation (access_token + refresh_token)
  - Auth endpoints: /auth/login, /auth/register, /auth/refresh, /auth/me
  - Default admin account: admin/admin123 (auto-created on first run)
  - Optional auth mode: controlled by AUTH_ENABLED env var (disabled by default)
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import jwt
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from api import database as db

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

JWT_SECRET = os.getenv("JWT_SECRET", "vulnpatch-default-secret-change-in-production")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24
REFRESH_TOKEN_EXPIRE_DAYS = 7

AUTH_ENABLED = os.getenv("AUTH_ENABLED", "false").lower() in ("true", "1", "yes")

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def _hash_password_bcrypt(password: str) -> tuple[str, str]:
    """Hash password using bcrypt. Returns (hash, salt)."""
    import bcrypt  # type: ignore[import-untyped]

    salt_bytes = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt_bytes)
    return hashed.decode("utf-8"), salt_bytes.decode("utf-8")


def _verify_password_bcrypt(password: str, password_hash: str, salt: str) -> bool:
    """Verify password against bcrypt hash."""
    import bcrypt  # type: ignore[import-untyped]

    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            password_hash.encode("utf-8"),
        )
    except Exception:
        return False


def _hash_password_sha256(password: str) -> tuple[str, str]:
    """Hash password using SHA-256 with salt (fallback). Returns (hash, salt)."""
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return hashed, salt


def _verify_password_sha256(password: str, password_hash: str, salt: str) -> bool:
    """Verify password against SHA-256 hash."""
    computed = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return secrets.compare_digest(computed, password_hash)


# Try bcrypt first, fall back to sha256
try:
    import bcrypt  # noqa: F401
    hash_password = _hash_password_bcrypt
    verify_password = _verify_password_bcrypt
    logger.info("Using bcrypt for password hashing")
except ImportError:
    hash_password = _hash_password_sha256
    verify_password = _verify_password_sha256
    logger.warning("bcrypt not installed, falling back to SHA-256 for password hashing")

# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(user_id: int, username: str, is_admin: bool) -> str:
    """Create a JWT access token."""
    payload = {
        "sub": str(user_id),
        "username": username,
        "is_admin": is_admin,
        "type": "access",
        "exp": _now_utc() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS),
        "iat": _now_utc(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: int) -> str:
    """Create a JWT refresh token."""
    payload = {
        "sub": str(user_id),
        "type": "refresh",
        "exp": _now_utc() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        "iat": _now_utc(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    """
    Decode and validate a JWT token.

    Raises HTTPException(401) on invalid/expired tokens.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

# ---------------------------------------------------------------------------
# Default admin account
# ---------------------------------------------------------------------------

_admin_created = False


def _ensure_default_admin() -> None:
    """Create the default admin account if it doesn't exist."""
    global _admin_created
    if _admin_created:
        return
    db.init_db()
    if not db.user_exists("admin"):
        password_hash, salt = hash_password("admin123")
        db.create_user(
            username="admin",
            password_hash=password_hash,
            salt=salt,
            is_admin=True,
        )
        logger.info("Default admin account created (admin/admin123)")
    _admin_created = True

# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserInfo(BaseModel):
    id: int
    username: str
    is_admin: bool
    created_at: str

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest) -> TokenResponse:
    """Authenticate a user and return JWT tokens."""
    _ensure_default_admin()

    user = db.get_user_by_username(body.username)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not verify_password(body.password, user["password_hash"], user["salt"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    access_token = create_access_token(user["id"], user["username"], user["is_admin"])
    refresh_token = create_refresh_token(user["id"])

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/register", response_model=TokenResponse)
def register(body: RegisterRequest) -> TokenResponse:
    """Register a new user and return JWT tokens."""
    _ensure_default_admin()

    if len(body.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(body.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    if db.user_exists(body.username):
        raise HTTPException(status_code=409, detail="Username already exists")

    password_hash, salt = hash_password(body.password)
    user_id = db.create_user(
        username=body.username,
        password_hash=password_hash,
        salt=salt,
        is_admin=False,
    )

    access_token = create_access_token(user_id, body.username, False)
    refresh_token = create_refresh_token(user_id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(body: RefreshRequest) -> TokenResponse:
    """Exchange a refresh token for a new access token (and new refresh token)."""
    payload = decode_token(body.refresh_token)

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")

    user_id = int(payload["sub"])
    user = db.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    access_token = create_access_token(user["id"], user["username"], user["is_admin"])
    new_refresh_token = create_refresh_token(user["id"])

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
    )


@router.get("/me", response_model=UserInfo)
def get_me(request: Request) -> UserInfo:
    """Get the current authenticated user's info."""
    # Extract token from Authorization header
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = auth_header[7:]
    payload = decode_token(token)

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")

    user_id = int(payload["sub"])
    user = db.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    return UserInfo(
        id=user["id"],
        username=user["username"],
        is_admin=user["is_admin"],
        created_at=user["created_at"],
    )


@router.get("/status")
def auth_status() -> dict[str, Any]:
    """Return the current authentication configuration status."""
    return {
        "auth_enabled": AUTH_ENABLED,
        "has_default_admin": db.user_exists("admin") if AUTH_ENABLED else False,
    }
