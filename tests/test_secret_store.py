from __future__ import annotations

import subprocess

import pytest

from github_credential_broker.errors import ConfigurationError
from github_credential_broker.policy import Capability, SecretSpec
from github_credential_broker.secret_store import SecretStore


def test_env_secret_store_resolves_capability(monkeypatch):
    monkeypatch.setenv("REAL_TOKEN", "secret-value")
    capability = Capability(
        name="deploy",
        description="",
        secrets=(SecretSpec(public_name="TOKEN", source="env", value="REAL_TOKEN"),),
    )

    assert SecretStore().resolve_capabilities((capability,)) == {"TOKEN": "secret-value"}


def test_env_secret_store_fails_closed(monkeypatch):
    monkeypatch.delenv("MISSING_TOKEN", raising=False)
    capability = Capability(
        name="deploy",
        description="",
        secrets=(SecretSpec(public_name="TOKEN", source="env", value="MISSING_TOKEN"),),
    )

    with pytest.raises(ConfigurationError):
        SecretStore().resolve_capabilities((capability,))


def test_secret_store_resolves_multiple_capabilities(monkeypatch):
    monkeypatch.setenv("DEPLOY_TOKEN", "deploy-secret")
    monkeypatch.setenv("CONFIG_TOKEN", "config-secret")
    deploy = Capability(
        name="deploy",
        description="",
        secrets=(SecretSpec(public_name="DEPLOY_TOKEN", source="env", value="DEPLOY_TOKEN"),),
    )
    config = Capability(
        name="config-write",
        description="",
        secrets=(SecretSpec(public_name="CONFIG_TOKEN", source="env", value="CONFIG_TOKEN"),),
    )

    assert SecretStore().resolve_capabilities((deploy, config)) == {
        "DEPLOY_TOKEN": "deploy-secret",
        "CONFIG_TOKEN": "config-secret",
    }


def test_secret_store_rejects_duplicate_response_names(monkeypatch):
    monkeypatch.setenv("FIRST_TOKEN", "first")
    monkeypatch.setenv("SECOND_TOKEN", "second")
    first = Capability(
        name="first",
        description="",
        secrets=(SecretSpec(public_name="TOKEN", source="env", value="FIRST_TOKEN"),),
    )
    second = Capability(
        name="second",
        description="",
        secrets=(SecretSpec(public_name="TOKEN", source="env", value="SECOND_TOKEN"),),
    )

    with pytest.raises(ConfigurationError, match="duplicate secret response name"):
        SecretStore().resolve_capabilities((first, second))


def test_secret_store_resolves_onepassword_reference():
    calls: list[list[str]] = []

    def fake_runner(command, **kwargs):
        calls.append(command)
        assert kwargs["check"] is False
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        assert kwargs["timeout"] == 7
        return subprocess.CompletedProcess(command, 0, stdout="secret-value", stderr="")

    capability = Capability(
        name="deploy",
        description="",
        secrets=(
            SecretSpec(
                public_name="TOKEN",
                source="op",
                value="op://broker-prod/deploy/token",
            ),
        ),
    )

    store = SecretStore(
        onepassword_cli_path="/usr/local/bin/op",
        onepassword_timeout_seconds=7,
        runner=fake_runner,
    )

    assert store.resolve_capabilities((capability,)) == {"TOKEN": "secret-value"}
    assert calls == [["/usr/local/bin/op", "read", "--no-newline", "op://broker-prod/deploy/token"]]


def test_secret_store_caches_onepassword_reference():
    calls = 0

    def fake_runner(command, **kwargs):
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(command, 0, stdout="secret-value", stderr="")

    capability = Capability(
        name="deploy",
        description="",
        secrets=(
            SecretSpec(
                public_name="TOKEN",
                source="op",
                value="op://broker-prod/deploy/token",
            ),
        ),
    )

    store = SecretStore(onepassword_cache_seconds=60, runner=fake_runner)

    assert store.resolve_capabilities((capability,)) == {"TOKEN": "secret-value"}
    assert store.resolve_capabilities((capability,)) == {"TOKEN": "secret-value"}
    assert calls == 1


def test_secret_store_reports_onepassword_failure():
    def fake_runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="nope")

    capability = Capability(
        name="deploy",
        description="",
        secrets=(
            SecretSpec(
                public_name="TOKEN",
                source="op",
                value="op://broker-prod/deploy/token",
            ),
        ),
    )

    with pytest.raises(ConfigurationError, match="1Password CLI failed"):
        SecretStore(runner=fake_runner).resolve_capabilities((capability,))
