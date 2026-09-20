"""WebAuthn/FIDO2 ceremonies with single-use Redis challenges.

Only public credential material is persisted. Challenges are tenant/user scoped,
short-lived and atomically consumed before verification to prevent replay.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import redis.asyncio as redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from cyberaudit.config import Settings
from cyberaudit.hardening_models import MfaFactor
from cyberaudit.models import User


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass(frozen=True)
class WebAuthnChallenge:
    challenge_id: str
    challenge: bytes
    organization_id: str
    user_id: str
    purpose: Literal["registration", "authentication", "step_up"]
    expires_at: datetime


class WebAuthnChallengeStore:
    def __init__(self, redis_url: str, ttl_seconds: int) -> None:
        self.client = redis.from_url(redis_url, decode_responses=True)
        self.ttl_seconds = ttl_seconds

    def _key(self, organization_id: str, challenge_id: str) -> str:
        tenant = hashlib.sha256(organization_id.encode()).hexdigest()[:24]
        return f"cyberaudit:webauthn:{tenant}:{challenge_id}"

    async def create(
        self,
        organization_id: str,
        user_id: str,
        purpose: Literal["registration", "authentication", "step_up"],
    ) -> WebAuthnChallenge:
        challenge = secrets.token_bytes(32)
        record = WebAuthnChallenge(
            challenge_id=secrets.token_urlsafe(24),
            challenge=challenge,
            organization_id=organization_id,
            user_id=user_id,
            purpose=purpose,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.ttl_seconds),
        )
        value = json.dumps(
            {
                "challenge": _b64url(record.challenge),
                "organization_id": organization_id,
                "user_id": user_id,
                "purpose": purpose,
                "expires_at": record.expires_at.isoformat(),
            },
            separators=(",", ":"),
        )
        created = await self.client.set(
            self._key(organization_id, record.challenge_id),
            value,
            ex=self.ttl_seconds,
            nx=True,
        )
        if not created:
            raise RuntimeError("Unable to allocate WebAuthn challenge")
        return record

    async def consume(
        self,
        organization_id: str,
        user_id: str,
        challenge_id: str,
        purpose: Literal["registration", "authentication", "step_up"],
    ) -> WebAuthnChallenge:
        raw = await self.client.getdel(self._key(organization_id, challenge_id))
        if not raw:
            raise ValueError("WebAuthn challenge is invalid, expired, or already used")
        data = json.loads(raw)
        expires_at = datetime.fromisoformat(data["expires_at"])
        if (
            data["organization_id"] != organization_id
            or data["user_id"] != user_id
            or data["purpose"] != purpose
            or expires_at <= datetime.now(timezone.utc)
        ):
            raise ValueError("WebAuthn challenge context mismatch")
        return WebAuthnChallenge(
            challenge_id,
            _b64url_decode(data["challenge"]),
            organization_id,
            user_id,
            purpose,
            expires_at,
        )


class WebAuthnService:
    def __init__(self, settings: Settings, store: WebAuthnChallengeStore | None = None) -> None:
        if not settings.webauthn_enabled:
            raise ValueError("WebAuthn is disabled")
        self.settings = settings
        self.store = store or WebAuthnChallengeStore(
            settings.redis_url,
            settings.webauthn_challenge_ttl_seconds,
        )

    async def registration_options(
        self, db: AsyncSession, user: User
    ) -> tuple[str, dict[str, Any]]:
        challenge = await self.store.create(user.organization_id, user.id, "registration")
        factors = list(
            (
                await db.scalars(
                    select(MfaFactor).where(
                        MfaFactor.organization_id == user.organization_id,
                        MfaFactor.user_id == user.id,
                        MfaFactor.factor_type == "webauthn",
                        MfaFactor.status == "active",
                    )
                )
            ).all()
        )
        exclude = [
            PublicKeyCredentialDescriptor(id=_b64url_decode(factor.credential_id))
            for factor in factors
            if factor.credential_id
        ]
        options = generate_registration_options(
            rp_id=self.settings.webauthn_rp_id,
            rp_name=self.settings.webauthn_rp_name,
            user_id=user.id.encode(),
            user_name=user.email,
            user_display_name=user.name,
            challenge=challenge.challenge,
            timeout=self.settings.webauthn_challenge_ttl_seconds * 1000,
            exclude_credentials=exclude,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                require_resident_key=False,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
        )
        return challenge.challenge_id, json.loads(options_to_json(options))

    async def verify_registration(
        self,
        db: AsyncSession,
        user: User,
        *,
        challenge_id: str,
        label: str,
        credential: dict[str, Any],
    ) -> MfaFactor:
        challenge = await self.store.consume(
            user.organization_id, user.id, challenge_id, "registration"
        )
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge.challenge,
            expected_rp_id=self.settings.webauthn_rp_id,
            expected_origin=self.settings.webauthn_origins,
            require_user_presence=True,
            require_user_verification=self.settings.webauthn_require_user_verification,
        )
        credential_id = _b64url(verification.credential_id)
        existing = await db.scalar(
            select(MfaFactor).where(
                MfaFactor.organization_id == user.organization_id,
                MfaFactor.credential_id == credential_id,
            )
        )
        if existing:
            raise ValueError("WebAuthn credential is already registered")
        transports = credential.get("response", {}).get("transports", [])
        allowed_transports = {
            "ble",
            "cable",
            "hybrid",
            "internal",
            "nfc",
            "smart-card",
            "usb",
        }
        factor = MfaFactor(
            organization_id=user.organization_id,
            user_id=user.id,
            factor_type="webauthn",
            label=label,
            credential_id=credential_id,
            public_key=_b64url(verification.credential_public_key),
            sign_count=verification.sign_count,
            transports=[value for value in transports if value in allowed_transports],
            aaguid=verification.aaguid,
            discoverable=bool(
                credential.get("clientExtensionResults", {}).get("credProps", {}).get("rk")
            ),
            backup_eligible=verification.credential_device_type.value == "multi_device",
            backup_state=verification.credential_backed_up,
            status="active",
            verified_at=datetime.now(timezone.utc),
        )
        db.add(factor)
        await db.flush()
        return factor

    async def authentication_options(
        self,
        db: AsyncSession,
        user: User,
        purpose: Literal["authentication", "step_up"] = "step_up",
    ) -> tuple[str, dict[str, Any]]:
        factors = list(
            (
                await db.scalars(
                    select(MfaFactor).where(
                        MfaFactor.organization_id == user.organization_id,
                        MfaFactor.user_id == user.id,
                        MfaFactor.factor_type == "webauthn",
                        MfaFactor.status == "active",
                    )
                )
            ).all()
        )
        if not factors:
            raise ValueError("No active WebAuthn credential")
        challenge = await self.store.create(user.organization_id, user.id, purpose)
        options = generate_authentication_options(
            rp_id=self.settings.webauthn_rp_id,
            challenge=challenge.challenge,
            timeout=self.settings.webauthn_challenge_ttl_seconds * 1000,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=_b64url_decode(factor.credential_id))
                for factor in factors
                if factor.credential_id
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return challenge.challenge_id, json.loads(options_to_json(options))

    async def verify_authentication(
        self,
        db: AsyncSession,
        user: User,
        *,
        challenge_id: str,
        credential: dict[str, Any],
        purpose: Literal["authentication", "step_up"] = "step_up",
    ) -> MfaFactor:
        challenge = await self.store.consume(user.organization_id, user.id, challenge_id, purpose)
        raw_credential_id = credential.get("rawId") or credential.get("id")
        if not isinstance(raw_credential_id, str):
            raise ValueError("Credential ID is missing")
        factor = await db.scalar(
            select(MfaFactor).where(
                MfaFactor.organization_id == user.organization_id,
                MfaFactor.user_id == user.id,
                MfaFactor.factor_type == "webauthn",
                MfaFactor.credential_id == raw_credential_id,
                MfaFactor.status == "active",
            )
        )
        if not factor or not factor.public_key:
            raise ValueError("WebAuthn credential is unavailable")
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge.challenge,
            expected_rp_id=self.settings.webauthn_rp_id,
            expected_origin=self.settings.webauthn_origins,
            credential_public_key=_b64url_decode(factor.public_key),
            credential_current_sign_count=factor.sign_count,
            require_user_verification=self.settings.webauthn_require_user_verification,
        )
        if (
            factor.sign_count > 0
            and verification.new_sign_count > 0
            and verification.new_sign_count <= factor.sign_count
        ):
            factor.status = "suspected_clone"
            raise ValueError("WebAuthn sign counter did not increase")
        factor.sign_count = max(factor.sign_count, verification.new_sign_count)
        factor.backup_state = verification.credential_backed_up
        factor.last_used_at = datetime.now(timezone.utc)
        await db.flush()
        return factor
