from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from github_credential_broker.errors import AuthorizationError, ConfigurationError
from github_credential_broker.policy import authorize_bundle, load_policy


def test_example_policy_loads():
    policy = load_policy(Path("config/policy.example.yml"))
    assert "github-credential-broker-smoke-test" in policy.bundles


def test_load_policy_and_authorize_exact_claims(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            defaults:
              audit_claims: [repository, ref]
            bundles:
              deploy:
                allow:
                  - repository: cesaregarza/SplatTop
                    ref: refs/heads/main
                secrets:
                  DIGITALOCEAN_ACCESS_TOKEN:
                    env: SPLATTOP_DO_TOKEN
            """
        ),
        encoding="utf-8",
    )

    policy = load_policy(policy_path)
    bundle = policy.require_bundle("deploy")
    authorize_bundle(bundle, {"repository": "cesaregarza/SplatTop", "ref": "refs/heads/main"})


def test_authorize_supports_globs(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            bundles:
              deploy:
                allow:
                  - repository: cesaregarza/SplatTop
                    ref: refs/tags/v*
                secrets:
                  TOKEN:
                    env: TOKEN
            """
        ),
        encoding="utf-8",
    )

    policy = load_policy(policy_path)
    authorize_bundle(
        policy.require_bundle("deploy"),
        {"repository": "cesaregarza/SplatTop", "ref": "refs/tags/v1.2.3"},
    )


def test_load_policy_supports_onepassword_secret_refs(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            bundles:
              deploy:
                allow:
                  - repository: cesaregarza/SplatTop
                secrets:
                  TOKEN:
                    op: op://broker-prod/deploy/token
            """
        ),
        encoding="utf-8",
    )

    policy = load_policy(policy_path)
    secret = policy.require_bundle("deploy").secrets[0]
    assert secret.public_name == "TOKEN"
    assert secret.source == "op"
    assert secret.value == "op://broker-prod/deploy/token"


def test_authorize_denies_missing_claim(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            bundles:
              deploy:
                allow:
                  - repository: cesaregarza/SplatTop
                    environment: production
                secrets:
                  TOKEN:
                    env: TOKEN
            """
        ),
        encoding="utf-8",
    )

    policy = load_policy(policy_path)
    with pytest.raises(AuthorizationError):
        authorize_bundle(policy.require_bundle("deploy"), {"repository": "cesaregarza/SplatTop"})


def test_authorize_denies_non_string_claim(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            bundles:
              deploy:
                allow:
                  - repository: cesaregarza/SplatTop
                secrets:
                  TOKEN:
                    env: TOKEN
            """
        ),
        encoding="utf-8",
    )

    policy = load_policy(policy_path)
    with pytest.raises(AuthorizationError):
        authorize_bundle(policy.require_bundle("deploy"), {"repository": ["cesaregarza/SplatTop"]})


def test_invalid_policy_requires_non_empty_allow(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            bundles:
              deploy:
                allow: []
                secrets:
                  TOKEN:
                    env: TOKEN
            """
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError):
        load_policy(policy_path)


def test_invalid_policy_rejects_repository_glob(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            bundles:
              deploy:
                allow:
                  - repository: cesaregarza/*
                secrets:
                  TOKEN:
                    env: TOKEN
            """
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="repository cannot use wildcards"):
        load_policy(policy_path)


def test_strict_mode_requires_repository_id(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            strict: true
            bundles:
              deploy:
                allow:
                  - repository: cesaregarza/SplatTop
                    ref: refs/heads/main
                secrets:
                  TOKEN:
                    env: TOKEN
            """
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="repository_id"):
        load_policy(policy_path)


def test_strict_mode_accepts_policy_with_repository_id(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            strict: true
            bundles:
              deploy:
                allow:
                  - repository: cesaregarza/SplatTop
                    repository_id: "12345"
                    ref: refs/heads/main
                secrets:
                  TOKEN:
                    env: TOKEN
            """
        ),
        encoding="utf-8",
    )

    policy = load_policy(policy_path)
    assert policy.strict is True
    authorize_bundle(
        policy.require_bundle("deploy"),
        {
            "repository": "cesaregarza/SplatTop",
            "repository_id": "12345",
            "ref": "refs/heads/main",
        },
    )


def test_invalid_policy_rejects_unsafe_secret_names(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            bundles:
              deploy:
                allow:
                  - repository: cesaregarza/SplatTop
                secrets:
                  TOKEN-WITH-DASH:
                    env: TOKEN
            """
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="shell-safe variable names"):
        load_policy(policy_path)


def test_invalid_policy_rejects_multiple_secret_sources(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            bundles:
              deploy:
                allow:
                  - repository: cesaregarza/SplatTop
                secrets:
                  TOKEN:
                    env: TOKEN
                    op: op://broker-prod/deploy/token
            """
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="exactly one"):
        load_policy(policy_path)


def test_invalid_policy_rejects_invalid_onepassword_ref(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            bundles:
              deploy:
                allow:
                  - repository: cesaregarza/SplatTop
                secrets:
                  TOKEN:
                    op: https://example.com/nope
            """
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="op:// secret reference"):
        load_policy(policy_path)


def test_invalid_policy_rejects_unknown_secret_keys(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            bundles:
              deploy:
                allow:
                  - repository: cesaregarza/SplatTop
                secrets:
                  TOKEN:
                    env: TOKEN
                    typo: ignored
            """
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="unsupported keys"):
        load_policy(policy_path)
