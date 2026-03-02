"""
auth.py — Authentication: login, JWT sessions, password hashing, lockout.
"""

import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps

import sqlalchemy as sa
from fastapi import Cookie, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from config import get
from database import AsyncSessionLocal, AuditLog, User

SECRET_KEY = get("server.secret_key", "changeme")
SESSION_HOURS = get("server.session_expire_hours", 24)
MAX_ATTEMPTS = get("security.max_login_attempts", 5)
LOCKOUT_MINS = get("security.lockout_minutes", 15)

# In-memory session store (suitable for single-server; use Redis for multi-node)
_sessions: dict = {}  # token -> {user_id, username, role, expires}


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return f"{salt}:{h.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split(":")
        expected = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
        return hmac.compare_digest(expected.hex(), h)
    except:
        return False


def create_session(user_id: int, username: str, role: str) -> str:
    token = secrets.token_urlsafe(48)
    expires = datetime.utcnow() + timedelta(hours=SESSION_HOURS)
    _sessions[token] = {
        "user_id": user_id, "username": username,
        "role": role, "expires": expires.timestamp()
    }
    return token


def get_session(token: str) -> dict | None:
    s = _sessions.get(token)
    if not s:
        return None
    if time.time() > s["expires"]:
        del _sessions[token]
        return None
    return s


def invalidate_session(token: str):
    _sessions.pop(token, None)


async def get_current_user(request: Request):
    """FastAPI dependency — reads session cookie and returns user info."""
    token = request.cookies.get("session")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    session = get_session(token)
    if not session:
        raise HTTPException(status_code=401, detail="Session expired")
    return session


async def require_role(roles: list):
    """Returns a dependency that checks user role."""
    async def _check(user=Depends(get_current_user)):
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return _check


async def log_audit(db, user_id: int | None, username: str, action: str,
                    detail: str = "", ip: str = ""):
    entry = AuditLog(user_id=user_id, username=username, action=action,
                     detail=detail[:500], ip_address=ip)
    db.add(entry)
    await db.commit()


async def create_default_admin():
    """Create default admin user if no users exist."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(sa.select(User).limit(1))
        if result.scalar_one_or_none():
            return
        admin = User(
            username="admin",
            password_hash=hash_password("admin123"),
            role="admin",
        )
        db.add(admin)
        await db.commit()
        print("  [AUTH] Default admin created: admin / admin123")
        print("  [AUTH] CHANGE THIS PASSWORD IMMEDIATELY after first login!")
