from __future__ import annotations

import subprocess

import pytest

from github_credential_broker.errors import ConfigurationError
from github_credential_broker.policy import Bundle, SecretSpec
from github_credential_broker.secret_store import SecretStore


def test_env_secret_store_resolves_bundle(monkeypatch):
    monkeypatch.setenv("REAL_TOKEN", "secret-value")
    bundle = Bundle(
        name="deploy",
        description="",
        allow=({"repository": "cesaregarza/SplatTop"},),
        secrets=(SecretSpec(public_name="TOKEN", source="env", value="REAL_TOKEN"),),
    )

    assert SecretStore().resolve_bundle(bundle) == {"TOKEN": "secret-value"}


def test_env_secret_store_fails_closed(monkeypatch):
    monkeypatch.delenv("MISSING_TOKEN", raising=False)
    bundle = Bundle(
        name="deploy",
        description="",
        allow=({"repository": "cesaregarza/SplatTop"},),
        secrets=(SecretSpec(public_name="TOKEN", source="env", value="MISSING_TOKEN"),),
    )

    with pytest.raises(ConfigurationError):
        SecretStore().resolve_bundle(bundle)


def test_secret_store_resolves_onepassword_reference():
    calls: list[list[str]] = []

    def fake_runner(command, **kwargs):
        calls.append(command)
        assert kwargs["check"] is False
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        assert kwargs["timeout"] == 7
        return subprocess.CompletedProcess(command, 0, stdout="secret-value", stderr="")

    bundle = Bundle(
        name="deploy",
        description="",
        allow=({"repository": "cesaregarza/SplatTop"},),
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

    assert store.resolve_bundle(bundle) == {"TOKEN": "secret-value"}
    assert calls == [["/usr/local/bin/op", "read", "--no-newline", "op://broker-prod/deploy/token"]]


def test_secret_store_caches_onepassword_reference():
    calls = 0

    def fake_runner(command, **kwargs):
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(command, 0, stdout="secret-value", stderr="")

    bundle = Bundle(
        name="deploy",
        description="",
        allow=({"repository": "cesaregarza/SplatTop"},),
        secrets=(
            SecretSpec(
                public_name="TOKEN",
                source="op",
                value="op://broker-prod/deploy/token",
            ),
        ),
    )

    store = SecretStore(onepassword_cache_seconds=60, runner=fake_runner)

    assert store.resolve_bundle(bundle) == {"TOKEN": "secret-value"}
    assert store.resolve_bundle(bundle) == {"TOKEN": "secret-value"}
    assert calls == 1


def test_secret_store_reports_onepassword_failure():
    def fake_runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="nope")

    bundle = Bundle(
        name="deploy",
        description="",
        allow=({"repository": "cesaregarza/SplatTop"},),
        secrets=(
            SecretSpec(
                public_name="TOKEN",
                source="op",
                value="op://broker-prod/deploy/token",
            ),
        ),
    )

    with pytest.raises(ConfigurationError, match="1Password CLI failed"):
        SecretStore(runner=fake_runner).resolve_bundle(bundle)
