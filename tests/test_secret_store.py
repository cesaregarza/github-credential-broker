from __future__ import annotations

import pytest

from github_credential_broker.errors import ConfigurationError
from github_credential_broker.policy import Bundle, SecretSpec
from github_credential_broker.secret_store import EnvSecretStore


def test_env_secret_store_resolves_bundle(monkeypatch):
    monkeypatch.setenv("REAL_TOKEN", "secret-value")
    bundle = Bundle(
        name="deploy",
        description="",
        allow=({"repository": "cesaregarza/SplatTop"},),
        secrets=(SecretSpec(public_name="TOKEN", env_name="REAL_TOKEN"),),
    )

    assert EnvSecretStore().resolve_bundle(bundle) == {"TOKEN": "secret-value"}


def test_env_secret_store_fails_closed(monkeypatch):
    monkeypatch.delenv("MISSING_TOKEN", raising=False)
    bundle = Bundle(
        name="deploy",
        description="",
        allow=({"repository": "cesaregarza/SplatTop"},),
        secrets=(SecretSpec(public_name="TOKEN", env_name="MISSING_TOKEN"),),
    )

    with pytest.raises(ConfigurationError):
        EnvSecretStore().resolve_bundle(bundle)

