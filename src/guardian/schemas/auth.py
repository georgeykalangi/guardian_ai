"""Authentication and RBAC schemas."""

from enum import StrEnum

from pydantic import BaseModel


class Role(StrEnum):
    ADMIN = "admin"
    AGENT = "agent"


class ApiKeyInfo(BaseModel):
    """Parsed API key with tenant and role metadata."""

    key: str
    tenant_id: str = "default"
    role: Role = Role.ADMIN
