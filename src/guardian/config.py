"""Application configuration via environment variables."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database
    database_url: str = "postgresql+asyncpg://guardian:guardian@localhost:5432/guardian"

    # Policy
    default_policy_path: str = "policies/default_policy.json"

    # LLM risk scorer
    llm_provider: str = "stub"  # "anthropic" | "openai" | "stub"
    llm_api_key: str = ""
    llm_model: str = "claude-sonnet-4-5-20250929"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"

    model_config = {"env_prefix": "GUARDIAN_", "env_file": ".env"}


settings = Settings()
