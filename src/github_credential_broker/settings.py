from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BROKER_", env_file=".env", extra="ignore")

    policy_path: Path = Field(default=Path("config/policy.yml"))
    expose_docs: bool = False
    github_oidc_issuer: str = "https://token.actions.githubusercontent.com"
    github_oidc_audience: str = Field(min_length=1)
    github_oidc_jwks_url: str = "https://token.actions.githubusercontent.com/.well-known/jwks"
    jwks_cache_seconds: int = Field(default=300, ge=60, le=86400)
    max_bearer_token_length: int = Field(default=16384, ge=512, le=65536)
    onepassword_cli_path: str = "op"
    onepassword_read_timeout_seconds: int = Field(default=10, ge=1, le=60)
    onepassword_cache_seconds: int = Field(default=60, ge=0, le=3600)


def load_settings() -> Settings:
    return Settings()
