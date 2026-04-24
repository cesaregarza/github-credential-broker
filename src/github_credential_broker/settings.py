from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BROKER_", env_file=".env", extra="ignore")

    policy_path: Path = Field(default=Path("config/policy.yml"))
    github_oidc_issuer: str = "https://token.actions.githubusercontent.com"
    github_oidc_audience: str = "github-credential-broker"
    github_oidc_jwks_url: str = (
        "https://token.actions.githubusercontent.com/.well-known/jwks"
    )
    jwks_cache_seconds: int = 300
    max_bundle_name_length: int = 80


def load_settings() -> Settings:
    return Settings()

