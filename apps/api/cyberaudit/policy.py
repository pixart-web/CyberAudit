import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cyberaudit.models import (
    AuthorizationDocument,
    Engagement,
    EngagementMode,
    EngagementStatus,
    Intensity,
    Organization,
    Scope,
    ScopeTarget,
    TargetType,
    User,
)
from cyberaudit.schemas import PolicyRequest, PolicyResponse

POLICY_VERSION = "1.0.0"
INTENSITY_ORDER = {
    Intensity.PASSIVE: 0,
    Intensity.LOW: 1,
    Intensity.NORMAL: 2,
    Intensity.ELEVATED: 3,
    Intensity.INTRUSIVE: 4,
}


def normalized_target(target_type: TargetType, value: str) -> str:
    value = value.strip().lower()
    if target_type in {TargetType.DOMAIN, TargetType.HOSTNAME}:
        return value.rstrip(".")
    if target_type == TargetType.URL:
        parsed = urlparse(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("invalid URL")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("invalid URL port") from exc
        hostname = parsed.hostname.encode("idna").decode("ascii").lower()
        if ":" in hostname:
            hostname = f"[{hostname}]"
        default_port = 443 if parsed.scheme == "https" else 80
        authority = hostname if port in {None, default_port} else f"{hostname}:{port}"
        return f"{parsed.scheme}://{authority}{parsed.path or '/'}"
    if target_type == TargetType.IP:
        return str(ipaddress.ip_address(value))
    if target_type == TargetType.CIDR:
        return str(ipaddress.ip_network(value, strict=False))
    return value


def is_private_destination(target_type: TargetType, value: str) -> bool:
    try:
        if target_type == TargetType.URL:
            hostname = urlparse(value).hostname
            if not hostname:
                return False
            lowered = hostname.rstrip(".").lower()
            if lowered == "localhost" or lowered.endswith((".local", ".internal", ".test")):
                return True
            value = hostname
        if target_type in {TargetType.IP, TargetType.CIDR, TargetType.URL}:
            network = ipaddress.ip_network(value, strict=False)
            return network.is_private or network.is_loopback
        if target_type in {TargetType.DOMAIN, TargetType.HOSTNAME}:
            lowered = value.rstrip(".").lower()
            return lowered in {"localhost"} or lowered.endswith((".local", ".internal", ".test"))
    except ValueError:
        return False
    return False


def target_matches(request_type: TargetType, request_value: str, target: ScopeTarget) -> bool:
    if not target.allowed:
        return False
    try:
        requested = normalized_target(request_type, request_value)
        if target.target_type == TargetType.CIDR and request_type == TargetType.IP:
            return ipaddress.ip_address(requested) in ipaddress.ip_network(target.normalized_value)
        if target.target_type in {TargetType.DOMAIN, TargetType.HOSTNAME}:
            exact = requested == target.normalized_value
            subdomain = target.include_subdomains and requested.endswith(
                f".{target.normalized_value}"
            )
            return exact or subdomain
        return request_type == target.target_type and requested == target.normalized_value
    except ValueError:
        return False


@dataclass
class PolicyContext:
    organization: Organization | None
    operator: User | None
    engagement: Engagement | None
    authorizations: list[AuthorizationDocument]
    scopes: list[Scope]
    targets: list[ScopeTarget]


class ScopePolicyEngine:
    async def load_context(self, db: AsyncSession, request: PolicyRequest) -> PolicyContext:
        organization = await db.get(Organization, request.organization_id)
        operator = await db.get(User, request.operator_id)
        engagement = await db.get(Engagement, request.engagement_id)
        authorizations = list(
            (
                await db.scalars(
                    select(AuthorizationDocument).where(
                        AuthorizationDocument.organization_id == request.organization_id,
                        AuthorizationDocument.engagement_id == request.engagement_id,
                    )
                )
            ).all()
        )
        scopes = list(
            (
                await db.scalars(
                    select(Scope).where(
                        Scope.organization_id == request.organization_id,
                        Scope.engagement_id == request.engagement_id,
                        Scope.deleted_at.is_(None),
                    )
                )
            ).all()
        )
        scope_ids = [scope.id for scope in scopes]
        targets = (
            list(
                (
                    await db.scalars(select(ScopeTarget).where(ScopeTarget.scope_id.in_(scope_ids)))
                ).all()
            )
            if scope_ids
            else []
        )
        return PolicyContext(organization, operator, engagement, authorizations, scopes, targets)

    async def evaluate(self, db: AsyncSession, request: PolicyRequest) -> PolicyResponse:
        return self.evaluate_context(request, await self.load_context(db, request))

    def evaluate_context(self, request: PolicyRequest, context: PolicyContext) -> PolicyResponse:
        denied: list[str] = []
        matched: list[str] = []
        now = request.requested_at
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        org = context.organization
        if not org or org.deleted_at or org.status != "active":
            denied.append("organization_inactive")
        else:
            matched.append("organization.active")

        user = context.operator
        if not user or user.deleted_at or user.status != "active":
            denied.append("operator_inactive")
        elif user.organization_id != request.organization_id:
            denied.append("operator_wrong_organization")
        else:
            matched.extend(["operator.active", "operator.tenant_match"])

        engagement = context.engagement
        if not engagement or engagement.deleted_at:
            denied.append("engagement_not_found")
        elif engagement.organization_id != request.organization_id:
            denied.append("engagement_wrong_organization")
        elif engagement.status not in {EngagementStatus.AUTHORIZED, EngagementStatus.ACTIVE}:
            denied.append("engagement_not_authorized")
        else:
            matched.extend(["engagement.tenant_match", "engagement.authorized_state"])

        today = now.date()
        valid_auth = any(
            auth.status == "valid" and auth.valid_from <= today <= auth.valid_until
            for auth in context.authorizations
        )
        if engagement and engagement.mode == EngagementMode.CLIENT:
            if not valid_auth:
                denied.append("authorization_missing_or_expired")
            else:
                matched.append("authorization.valid")

        active_scopes = [scope for scope in context.scopes if scope.status == "active"]
        if not active_scopes:
            denied.append("active_scope_missing")
        matching_scopes: list[Scope] = []
        for scope in active_scopes:
            scope_targets = [item for item in context.targets if item.scope_id == scope.id]
            if any(
                target_matches(request.target_type, request.target_value, item)
                for item in scope_targets
            ):
                matching_scopes.append(scope)
        if not matching_scopes:
            denied.append("target_out_of_scope")
        else:
            matched.append("target.in_scope")

        eligible: list[Scope] = []
        for scope in matching_scopes:
            if scope.emergency_stop_enabled:
                continue
            local_time = now.astimezone(ZoneInfo(scope.timezone)).time().replace(tzinfo=None)
            if scope.allowed_start_time and scope.allowed_end_time:
                if scope.allowed_start_time <= scope.allowed_end_time:
                    in_window = scope.allowed_start_time <= local_time <= scope.allowed_end_time
                else:
                    in_window = (
                        local_time >= scope.allowed_start_time
                        or local_time <= scope.allowed_end_time
                    )
                if not in_window:
                    continue
            if (
                INTENSITY_ORDER[request.requested_intensity]
                > INTENSITY_ORDER[scope.maximum_intensity]
            ):
                continue
            if scope.allowed_techniques and request.technique not in scope.allowed_techniques:
                continue
            eligible.append(scope)
        if matching_scopes and not eligible:
            if any(scope.emergency_stop_enabled for scope in matching_scopes):
                denied.append("emergency_stop_enabled")
            if all(
                INTENSITY_ORDER[request.requested_intensity]
                > INTENSITY_ORDER[scope.maximum_intensity]
                for scope in matching_scopes
            ):
                denied.append("intensity_exceeds_scope")
            if all(
                scope.allowed_techniques and request.technique not in scope.allowed_techniques
                for scope in matching_scopes
            ):
                denied.append("technique_not_allowed")
            if not denied:
                denied.append("outside_allowed_hours")
        elif eligible:
            matched.extend(
                [
                    "scope.active",
                    "scope.schedule",
                    "scope.intensity",
                    "scope.technique",
                    "emergency_stop.off",
                ]
            )

        if engagement and engagement.mode == EngagementMode.LABORATORY:
            if not is_private_destination(request.target_type, request.target_value):
                denied.append("laboratory_public_destination")
            else:
                matched.append("laboratory.private_destination")

        requires_approval = request.requested_intensity in {Intensity.ELEVATED, Intensity.INTRUSIVE}
        decision: Literal["allowed", "denied", "requires_approval"] = (
            "denied"
            if denied
            else (
                "requires_approval" if requires_approval and not request.approval_id else "allowed"
            )
        )
        reasons = denied or (
            ["elevated_intensity_requires_approval"] if decision == "requires_approval" else []
        )
        if request.approval_id:
            matched.append("approval.present")
        return PolicyResponse(
            decision=decision,
            reasons=reasons,
            matched_rules=matched,
            evaluated_at=datetime.now(timezone.utc),
            policy_version=POLICY_VERSION,
        )
