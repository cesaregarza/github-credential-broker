from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from github_credential_broker.errors import AuthorizationError, ConfigurationError
from github_credential_broker.policy import authorize_capabilities, load_policy


def test_example_policy_loads():
    policy = load_policy(Path("config/policy.example.yml"))
    capability = policy.require_capability("broker-smoke-test")
    assert policy.strict is True
    assert capability.secrets[0].public_name == "TEST_TOKEN"
    assert capability.secrets[0].source == "env"
    assert capability.secrets[0].value == "TEST_TOKEN"


def test_load_policy_and_authorize_exact_claims(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            defaults:
              audit_claims: [repository, ref]
            capabilities:
              deploy:
                secrets:
                  DIGITALOCEAN_ACCESS_TOKEN:
                    env: SPLATTOP_DO_TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                    ref: refs/heads/main
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )

    policy = load_policy(policy_path)
    capabilities = authorize_capabilities(
        policy,
        ["deploy"],
        {"repository": "cesaregarza/SplatTop", "ref": "refs/heads/main"},
    )
    assert capabilities[0].name == "deploy"


def test_authorize_supports_globs(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                    ref: refs/tags/v*
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )

    policy = load_policy(policy_path)
    authorize_capabilities(
        policy,
        ["deploy"],
        {"repository": "cesaregarza/SplatTop", "ref": "refs/tags/v1.2.3"},
    )


def test_load_policy_supports_onepassword_secret_refs(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    op: op://broker-prod/deploy/token
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )

    policy = load_policy(policy_path)
    secret = policy.require_capability("deploy").secrets[0]
    assert secret.public_name == "TOKEN"
    assert secret.source == "op"
    assert secret.value == "op://broker-prod/deploy/token"


def test_load_policy_supports_legacy_bundles_for_migration(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
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

    policy = load_policy(policy_path)
    capabilities = authorize_capabilities(
        policy,
        ["deploy"],
        {"repository": "cesaregarza/SplatTop", "ref": "refs/heads/main"},
    )

    assert capabilities[0].name == "deploy"
    assert capabilities[0].secrets[0].public_name == "TOKEN"
    assert len(policy.grants) == 1


def test_invalid_policy_rejects_mixed_legacy_and_capability_schema(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: TOKEN
            bundles:
              old-deploy:
                allow:
                  - repository: cesaregarza/SplatTop
                secrets:
                  TOKEN:
                    env: TOKEN
            """
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="cannot mix"):
        load_policy(policy_path)


def test_authorize_denies_missing_claim(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                    environment: production
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )

    policy = load_policy(policy_path)
    with pytest.raises(AuthorizationError):
        authorize_capabilities(policy, ["deploy"], {"repository": "cesaregarza/SplatTop"})


def test_authorize_denies_non_string_claim(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )

    policy = load_policy(policy_path)
    with pytest.raises(AuthorizationError):
        authorize_capabilities(policy, ["deploy"], {"repository": ["cesaregarza/SplatTop"]})


def test_authorize_allows_capability_union_from_matching_grants(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                secrets:
                  DEPLOY_TOKEN:
                    env: DEPLOY_TOKEN
              config-write:
                secrets:
                  CONFIG_TOKEN:
                    env: CONFIG_TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                capabilities: [deploy]
              - allow:
                  - repository: cesaregarza/SplatTop
                    ref: refs/heads/main
                capabilities: [config-write]
            """
        ),
        encoding="utf-8",
    )

    policy = load_policy(policy_path)
    capabilities = authorize_capabilities(
        policy,
        ["deploy", "config-write"],
        {"repository": "cesaregarza/SplatTop", "ref": "refs/heads/main"},
    )

    assert [capability.name for capability in capabilities] == ["deploy", "config-write"]


def test_authorize_denies_ungranted_requested_capability(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                secrets:
                  DEPLOY_TOKEN:
                    env: DEPLOY_TOKEN
              config-write:
                secrets:
                  CONFIG_TOKEN:
                    env: CONFIG_TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )

    policy = load_policy(policy_path)
    with pytest.raises(AuthorizationError):
        authorize_capabilities(
            policy,
            ["deploy", "config-write"],
            {"repository": "cesaregarza/SplatTop"},
        )


def test_invalid_policy_requires_non_empty_allow(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: TOKEN
            grants:
              - allow: []
                capabilities: [deploy]
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
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/*
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="repository cannot use wildcards"):
        load_policy(policy_path)


def test_invalid_policy_rejects_unknown_grant_capability(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                capabilities: [missing]
            """
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="unknown capability"):
        load_policy(policy_path)


def test_invalid_policy_rejects_duplicate_grant_capability(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                capabilities: [deploy, deploy]
            """
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="duplicates"):
        load_policy(policy_path)


def test_strict_mode_requires_repository_id(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            strict: true
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                    ref: refs/heads/main
                capabilities: [deploy]
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
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                    repository_id: "12345"
                    ref: refs/heads/main
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )

    policy = load_policy(policy_path)
    assert policy.strict is True
    authorize_capabilities(
        policy,
        ["deploy"],
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
            capabilities:
              deploy:
                secrets:
                  TOKEN-WITH-DASH:
                    env: TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                capabilities: [deploy]
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
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: TOKEN
                    op: op://broker-prod/deploy/token
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                capabilities: [deploy]
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
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    op: https://example.com/nope
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                capabilities: [deploy]
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
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: TOKEN
                    typo: ignored
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="unsupported keys"):
        load_policy(policy_path)
