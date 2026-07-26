from datetime import date, datetime, time
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from cyberaudit.models import Criticality, EngagementMode, EngagementStatus, Intensity, TargetType

T = TypeVar("T")


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(ORMModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int


class OrganizationRead(ORMModel):
    id: str
    name: str
    slug: str
    status: str
    timezone: str
    locale: str
    created_at: datetime


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    slug: str = Field(pattern=r"^[a-z0-9-]+$", max_length=80)
    timezone: str = "Europe/Lisbon"
    locale: Literal["pt-PT", "en"] = "pt-PT"


class UserRead(ORMModel):
    id: str
    organization_id: str
    name: str
    email: EmailStr
    status: str
    mfa_enabled: bool


class UserCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    role: str = "Auditor"


class ClientCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    legal_name: str | None = None
    tax_number: str | None = None
    email: EmailStr | None = None
    phone: str | None = None
    address: str | None = None
    status: str = "active"
    notes: str | None = None


class ClientRead(ClientCreate, ORMModel):
    id: str
    organization_id: str
    created_at: datetime


class EngagementCreate(BaseModel):
    client_id: str
    name: str = Field(min_length=3, max_length=160)
    code: str = Field(pattern=r"^[A-Z0-9-]+$", max_length=40)
    description: str | None = None
    mode: EngagementMode
    start_date: date | None = None
    end_date: date | None = None
    owner_id: str | None = None
    risk_level: Criticality = Criticality.MEDIUM
    notes: str | None = None

    @field_validator("end_date")
    @classmethod
    def valid_dates(cls, value: date | None, info: Any) -> date | None:
        start = info.data.get("start_date")
        if value and start and value < start:
            raise ValueError("end_date must not precede start_date")
        return value


class EngagementRead(EngagementCreate, ORMModel):
    id: str
    organization_id: str
    status: EngagementStatus
    created_at: datetime


class StateChange(BaseModel):
    status: EngagementStatus


class ScopeCreate(BaseModel):
    engagement_id: str
    name: str = Field(min_length=2, max_length=160)
    description: str | None = None
    status: str = "active"
    allowed_start_time: time | None = None
    allowed_end_time: time | None = None
    timezone: str = "Europe/Lisbon"
    maximum_intensity: Intensity = Intensity.NORMAL
    emergency_stop_enabled: bool = False
    allowed_techniques: list[str] = Field(default_factory=list)


class ScopeRead(ScopeCreate, ORMModel):
    id: str
    organization_id: str
    created_at: datetime


class TargetCreate(BaseModel):
    scope_id: str
    target_type: TargetType
    target_value: str = Field(min_length=1, max_length=500)
    include_subdomains: bool = False
    allowed: bool = True
    notes: str | None = None


class TargetRead(TargetCreate, ORMModel):
    id: str
    normalized_value: str
    created_at: datetime


class AssetCreate(BaseModel):
    engagement_id: str
    name: str
    asset_type: str
    identifier: str
    hostname: str | None = None
    ip_address: str | None = None
    domain: str | None = None
    operating_system: str | None = None
    owner: str | None = None
    criticality: Criticality = Criticality.MEDIUM
    status: str = "active"


class AssetRead(AssetCreate, ORMModel):
    id: str
    organization_id: str
    created_at: datetime


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+$")
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class PolicyRequest(BaseModel):
    organization_id: str
    engagement_id: str
    operator_id: str
    target_type: TargetType
    target_value: str
    technique: str
    requested_intensity: Intensity
    requested_at: datetime
    approval_id: str | None = None


class PolicyResponse(BaseModel):
    decision: Literal["allowed", "denied", "requires_approval"]
    reasons: list[str]
    matched_rules: list[str]
    evaluated_at: datetime
    policy_version: str
