"""Central, explainable and deny-by-default authorization policy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from cyberaudit.models import User

SENSITIVE_PERMISSIONS = {
    "enterprise_connectors.manage",
    "enterprise_credentials.manage",
    "enterprise_exports.create",
    "roles.manage",
    "users.manage",
}


@dataclass(frozen=True)
class AuthorizationDecision:
    decision: Literal["allow", "deny"]
    reason_code: str
    policy_version: str = "authorization-1.0.0"


class AuthorizationPolicyEngine:
    def evaluate(
        self,
        *,
        actor: User | None,
        organization_id: str,
        permission: str,
        resource: Any = None,
        action: str = "read",
        authentication_strength: str = "single_factor",
        request_origin: str = "api",
    ) -> AuthorizationDecision:
        if actor is None or actor.status != "active" or actor.deleted_at:
            return AuthorizationDecision("deny", "ACTOR_INACTIVE")
        if actor.organization_id != organization_id:
            return AuthorizationDecision("deny", "CROSS_TENANT")
        granted = {item.code for role in actor.roles for item in role.permissions}
        if permission not in granted:
            return AuthorizationDecision("deny", "PERMISSION_MISSING")
        resource_organization = getattr(resource, "organization_id", organization_id)
        if resource_organization != organization_id:
            return AuthorizationDecision("deny", "RESOURCE_CROSS_TENANT")
        if permission in SENSITIVE_PERMISSIONS and authentication_strength not in {
            "mfa",
            "phishing_resistant",
        }:
            return AuthorizationDecision("deny", "STEP_UP_REQUIRED")
        if request_origin not in {"api", "worker", "system"}:
            return AuthorizationDecision("deny", "ORIGIN_INVALID")
        if action.startswith("delete") and authentication_strength != "phishing_resistant":
            return AuthorizationDecision("deny", "PHISHING_RESISTANT_REQUIRED")
        return AuthorizationDecision("allow", "POLICY_ALLOWED")
