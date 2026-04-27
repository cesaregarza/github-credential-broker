from __future__ import annotations

from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BROKER_", env_file=".env", extra="ignore")

    policy_path: Path = Field(default=Path("config/policy.yml"))
    expose_docs: bool = False
    github_oidc_issuer: str = "https://token.actions.githubusercontent.com"
    github_oidc_audience: str = Field(min_length=1)
    github_oidc_jwks_url: str = "https://token.actions.githubusercontent.com/.well-known/jwks"
    jwks_cache_seconds: int = Field(default=300, ge=60, le=86400)
    require_jti: bool = True
    max_bearer_token_length: int = Field(default=16384, ge=512, le=65536)
    onepassword_cli_path: str = "op"
    onepassword_read_timeout_seconds: int = Field(default=10, ge=1, le=60)
    onepassword_cache_seconds: int = Field(default=60, ge=0, le=3600)
    readiness_check_secret_resolution: bool = False
    enable_legacy_credentials: bool = False
    rate_limit_enabled: bool = True
    rate_limit_ip_per_minute: int = Field(default=60, ge=1, le=10000)
    rate_limit_identity_per_minute: int = Field(default=30, ge=1, le=10000)
    trusted_proxy_cidrs: tuple[str, ...] = ()

    @field_validator("trusted_proxy_cidrs", mode="before")
    @classmethod
    def parse_trusted_proxy_cidrs(cls, value):
        if value is None or value == "":
            return ()
        if isinstance(value, str):
            return tuple(item.strip() for item in value.split(",") if item.strip())
        return value


def load_settings() -> Settings:
    return Settings()
