"""OIDC PKCE, TOTP, recovery code and server-side session primitives."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
import redis.asyncio as redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.config import Settings
from cyberaudit.hardening_models import UserSession
from cyberaudit.models import User


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    return verifier, challenge


@dataclass(frozen=True)
class OidcTransaction:
    state: str
    nonce: str
    verifier_hash: str
    organization_id: str
    expires_at: datetime


class OidcClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        if not settings.oidc_enabled or not settings.oidc_issuer:
            raise ValueError("OIDC is disabled")
        self.issuer = settings.oidc_issuer.rstrip("/")
        self.transport = transport

    def _client(self, timeout: float) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            verify=True,
            transport=self.transport,
        )

    async def discovery(self) -> dict[str, Any]:
        url = f"{self.issuer}/.well-known/openid-configuration"
        async with self._client(10) as client:
            response = await client.get(url, headers={"accept": "application/json"})
            response.raise_for_status()
            document = response.json()
        if document.get("issuer", "").rstrip("/") != self.issuer:
            raise ValueError("OIDC discovery issuer mismatch")
        for endpoint in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not str(document.get(endpoint, "")).startswith(f"{self.issuer}/"):
                raise ValueError(f"OIDC {endpoint} is outside the configured issuer")
        return document

    async def authorization_url(self, transaction: OidcTransaction, code_challenge: str) -> str:
        discovery = await self.discovery()
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self.settings.oidc_client_id,
                "redirect_uri": self.settings.oidc_redirect_uri,
                "scope": " ".join(self.settings.oidc_scopes),
                "state": transaction.state,
                "nonce": transaction.nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        return f"{discovery['authorization_endpoint']}?{query}"

    async def exchange_and_validate(
        self,
        *,
        code: str,
        verifier: str,
        transaction: OidcTransaction,
        client_secret: str | None = None,
    ) -> dict[str, Any]:
        if transaction.expires_at <= datetime.now(timezone.utc):
            raise ValueError("OIDC transaction expired")
        if not hmac.compare_digest(
            transaction.verifier_hash, hashlib.sha256(verifier.encode()).hexdigest()
        ):
            raise ValueError("PKCE verifier mismatch")
        discovery = await self.discovery()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self.settings.oidc_client_id,
            "redirect_uri": self.settings.oidc_redirect_uri,
            "code_verifier": verifier,
        }
        if client_secret:
            data["client_secret"] = client_secret
        async with self._client(15) as client:
            token_response = await client.post(discovery["token_endpoint"], data=data)
            token_response.raise_for_status()
            token_payload = token_response.json()
            jwks_response = await client.get(discovery["jwks_uri"])
            jwks_response.raise_for_status()
        id_token = token_payload.get("id_token")
        if not isinstance(id_token, str):
            raise ValueError("OIDC response did not include an ID token")
        header = jwt.get_unverified_header(id_token)
        keys = jwt.PyJWKSet.from_dict(jwks_response.json()).keys
        key = next((item.key for item in keys if item.key_id == header.get("kid")), None)
        if key is None:
            raise ValueError("OIDC signing key is unknown")
        claims = jwt.decode(
            id_token,
            key,
            algorithms=["RS256", "ES256"],
            audience=self.settings.oidc_client_id,
            issuer=self.issuer,
            leeway=60,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]},
        )
        if not hmac.compare_digest(str(claims["nonce"]), transaction.nonce):
            raise ValueError("OIDC nonce mismatch")
        email = str(claims.get("email", "")).lower()
        if not email or "@" not in email:
            raise ValueError("OIDC email claim is missing")
        if self.settings.oidc_require_verified_email and claims.get("email_verified") is not True:
            raise ValueError("OIDC email is not verified")
        if (
            claims.get("account_status") in {"suspended", "disabled", "locked"}
            or claims.get("active") is False
        ):
            raise ValueError("OIDC account is inactive")
        if self.settings.oidc_allowed_domains:
            domain = email.rsplit("@", 1)[-1]
            if domain not in self.settings.oidc_allowed_domains:
                raise ValueError("OIDC email domain is not allowed")
        raw_groups = claims.get("groups") or []
        if not isinstance(raw_groups, list) or any(
            not isinstance(group, str) for group in raw_groups
        ):
            raise ValueError("OIDC groups claim is invalid")
        if len(raw_groups) > self.settings.oidc_max_groups:
            raise ValueError("OIDC groups claim exceeds its configured limit")
        groups = set(raw_groups)
        if self.settings.oidc_required_group and self.settings.oidc_required_group not in groups:
            raise ValueError("Required OIDC group is missing")
        return claims

    def mapped_roles(self, claims: dict[str, Any]) -> set[str]:
        raw_groups = claims.get("groups") or []
        if not isinstance(raw_groups, list):
            return set()
        allowed_roles = {"Client", "Reviewer", "Auditor", "Administrator"}
        return {
            role
            for group in raw_groups
            if isinstance(group, str)
            and (role := self.settings.oidc_group_role_mapping.get(group)) in allowed_roles
        }


class OidcStateStore:
    """Single-use, namespaced OIDC state in Redis; no token or secret is stored."""

    def __init__(self, redis_url: str) -> None:
        self.client = redis.from_url(redis_url, decode_responses=True)

    async def create(
        self, organization_id: str, verifier_hash: str, ttl_seconds: int = 600
    ) -> OidcTransaction:
        transaction = OidcTransaction(
            state=secrets.token_urlsafe(32),
            nonce=secrets.token_urlsafe(32),
            verifier_hash=verifier_hash,
            organization_id=organization_id,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
        )
        organization_hash = hashlib.sha256(organization_id.encode()).hexdigest()[:24]
        key = f"cyberaudit:oidc:{organization_hash}:{transaction.state}"
        value = "|".join(
            [
                transaction.nonce,
                transaction.verifier_hash,
                transaction.organization_id,
                transaction.expires_at.isoformat(),
            ]
        )
        await self.client.set(key, value, ex=ttl_seconds, nx=True)
        return transaction

    async def consume(self, organization_id: str, state: str) -> OidcTransaction:
        organization_hash = hashlib.sha256(organization_id.encode()).hexdigest()[:24]
        key = f"cyberaudit:oidc:{organization_hash}:{state}"
        value = await self.client.getdel(key)
        if not value:
            raise ValueError("OIDC state is invalid or already used")
        nonce, verifier_hash, stored_organization, expires_at = value.split("|", 3)
        if stored_organization != organization_id:
            raise ValueError("OIDC state tenant mismatch")
        return OidcTransaction(
            state,
            nonce,
            verifier_hash,
            stored_organization,
            datetime.fromisoformat(expires_at),
        )


def verify_totp(secret: str, code: str, *, at_time: int | None = None, window: int = 1) -> bool:
    if not code.isdigit() or len(code) != 6:
        return False
    timestamp = at_time or int(time.time())
    try:
        key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    except (ValueError, TypeError):
        return False
    for offset in range(-window, window + 1):
        counter = (timestamp // 30) + offset
        digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
        position = digest[-1] & 0x0F
        value = (int.from_bytes(digest[position : position + 4], "big") & 0x7FFFFFFF) % 1_000_000
        if hmac.compare_digest(f"{value:06d}", code):
            return True
    return False


def generate_recovery_codes(count: int = 10) -> tuple[list[str], list[str]]:
    if not 5 <= count <= 20:
        raise ValueError("Recovery code count must be between 5 and 20")
    codes = [secrets.token_hex(6) for _ in range(count)]
    hashes = [hashlib.sha256(code.encode()).hexdigest() for code in codes]
    return codes, hashes


def consume_recovery_code(code: str, hashes: list[str]) -> int | None:
    candidate = hashlib.sha256(code.encode()).hexdigest()
    return next(
        (index for index, stored in enumerate(hashes) if hmac.compare_digest(stored, candidate)),
        None,
    )


class SessionService:
    @staticmethod
    async def create(
        db: AsyncSession,
        user: User,
        settings: Settings,
        *,
        authentication_method: str,
        authentication_strength: str,
        source_ip: str | None = None,
        user_agent_family: str | None = None,
    ) -> tuple[UserSession, str, str]:
        active = list(
            (
                await db.scalars(
                    select(UserSession)
                    .where(
                        UserSession.organization_id == user.organization_id,
                        UserSession.user_id == user.id,
                        UserSession.status == "active",
                    )
                    .order_by(UserSession.last_seen_at.asc())
                )
            ).all()
        )
        while len(active) >= settings.maximum_sessions_per_user:
            oldest = active.pop(0)
            oldest.status = "revoked"
            oldest.revoked_at = datetime.now(timezone.utc)
            oldest.revoke_reason = "session_limit"
        raw_session = secrets.token_urlsafe(48)
        csrf = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        session = UserSession(
            organization_id=user.organization_id,
            user_id=user.id,
            session_token_hash=hashlib.sha256(raw_session.encode()).hexdigest(),
            csrf_token_hash=hashlib.sha256(csrf.encode()).hexdigest(),
            authentication_method=authentication_method,
            authentication_strength=authentication_strength,
            source_ip_hash=(
                hmac.new(
                    settings.encryption_key.encode(), source_ip.encode(), hashlib.sha256
                ).hexdigest()
                if source_ip
                else None
            ),
            user_agent_family=user_agent_family,
            idle_expires_at=now + timedelta(minutes=settings.session_idle_minutes),
            absolute_expires_at=now + timedelta(hours=settings.session_absolute_hours),
        )
        db.add(session)
        await db.flush()
        return session, raw_session, csrf

    @staticmethod
    async def authenticate(
        db: AsyncSession, raw_session: str, csrf: str | None = None
    ) -> UserSession | None:
        digest = hashlib.sha256(raw_session.encode()).hexdigest()
        session = await db.scalar(
            select(UserSession).where(
                UserSession.session_token_hash == digest,
                UserSession.status == "active",
            )
        )
        now = datetime.now(timezone.utc)
        if not session or session.idle_expires_at <= now or session.absolute_expires_at <= now:
            if session:
                session.status = "expired"
            return None
        if csrf and not hmac.compare_digest(
            session.csrf_token_hash, hashlib.sha256(csrf.encode()).hexdigest()
        ):
            return None
        session.last_seen_at = now
        return session

    @staticmethod
    async def revoke_all(db: AsyncSession, user: User, actor_id: str) -> int:
        sessions = list(
            (
                await db.scalars(
                    select(UserSession).where(
                        UserSession.organization_id == user.organization_id,
                        UserSession.user_id == user.id,
                        UserSession.status == "active",
                    )
                )
            ).all()
        )
        now = datetime.now(timezone.utc)
        for session in sessions:
            session.status = "revoked"
            session.revoked_at = now
            session.revoked_by = actor_id
            session.revoke_reason = "remote_logout"
        return len(sessions)
