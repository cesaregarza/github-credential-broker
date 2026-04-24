from __future__ import annotations

import textwrap

import pytest

from github_credential_broker.errors import AuthorizationError, ConfigurationError
from github_credential_broker.policy import authorize_bundle, load_policy


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
