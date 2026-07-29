import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext  # type: ignore[import-untyped]
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.config import get_settings
from cyberaudit.db import get_db
from cyberaudit.models import RefreshToken, User

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except (TypeError, ValueError):
        return False


def create_access_token(user: User) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.id,
        "org": user.organization_id,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_minutes),
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_token(token: str, expected_type: str = "access") -> dict[str, Any]:
    try:
        payload = jwt.decode(token, get_settings().jwt_secret, algorithms=["HS256"])
        if payload.get("type") != expected_type:
            raise ValueError("invalid token type")
        return payload
    except (jwt.PyJWTError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        ) from exc


async def issue_refresh_token(db: AsyncSession, user: User, family_id: str | None = None) -> str:
    raw = secrets.token_urlsafe(48)
    token = RefreshToken(
        user_id=user.id,
        family_id=family_id or str(uuid.uuid4()),
        token_hash=hashlib.sha256(raw.encode()).hexdigest(),
        expires_at=datetime.now(timezone.utc) + timedelta(days=get_settings().refresh_token_days),
    )
    db.add(token)
    await db.flush()
    return f"{token.id}.{raw}"


async def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    payload = decode_token(credentials.credentials)
    user = await db.get(User, payload["sub"])
    if not user or user.status != "active" or user.deleted_at:
        raise HTTPException(status_code=401, detail="Inactive user")
    if user.organization_id != payload.get("org"):
        raise HTTPException(status_code=401, detail="Tenant mismatch")
    return user


def require_permission(code: str):
    async def dependency(user: User = Depends(current_user)) -> User:
        granted = {permission.code for role in user.roles for permission in role.permissions}
        if code not in granted:
            raise HTTPException(status_code=403, detail=f"Missing permission: {code}")
        return user

    return dependency
