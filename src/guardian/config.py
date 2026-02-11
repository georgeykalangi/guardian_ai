"""Application configuration via environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings

from guardian.schemas.auth import ApiKeyInfo, Role


class Settings(BaseSettings):
    # Database
    database_url: str = "postgresql+asyncpg://guardian:guardian@localhost:5432/guardian"

    # Policy
    default_policy_path: str = "policies/default_policy.json"

    # LLM risk scorer
    llm_provider: str = "stub"  # "anthropic" | "openai" | "stub"
    llm_api_key: str = ""
    llm_model: str = "claude-sonnet-4-5-20250929"

    # Authentication
    api_keys: str = ""  # Comma-separated valid API keys; empty = auth disabled (dev mode)

    # Rate limiting
    rate_limit_rpm: int = 60  # Requests per minute; 0 = disabled

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"
    cors_origins: list[str] = ["*"]

    model_config = {"env_prefix": "GUARDIAN_", "env_file": ".env"}

    def parse_api_keys(self) -> dict[str, ApiKeyInfo]:
        """Parse api_keys string into a mapping of key -> ApiKeyInfo.

        Formats:
          - "key1,key2"                     -> bare keys, default tenant + admin
          - "key1:tenant1:admin,key2:t2:agent" -> structured keys
          - Mixed is allowed
        """
        raw = self.api_keys.strip()
        if not raw:
            return {}
        result: dict[str, ApiKeyInfo] = {}
        for entry in raw.split(","):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split(":")
            if len(parts) == 3:
                key, tenant, role_str = parts
                result[key] = ApiKeyInfo(key=key, tenant_id=tenant, role=Role(role_str))
            else:
                # Bare key -> default:admin
                result[entry] = ApiKeyInfo(key=entry, tenant_id="default", role=Role.ADMIN)
        return result


settings = Settings()
