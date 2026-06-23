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


def test_real_policy_loads():
    policy = load_policy(Path("config/policy.yml"))
    capability = policy.require_capability("broker-smoke-test")
    assert policy.strict is True
    assert capability.secrets[0].public_name == "TEST_TOKEN"
    assert capability.secrets[0].source == "env"
    assert capability.secrets[0].value == "TEST_TOKEN"


def test_real_policy_capability_names_are_kebab_case():
    policy = load_policy(Path("config/policy.yml"))
    assert all("_" not in name for name in policy.capabilities)


def test_rankings_spaces_destination_uses_shared_spaces_credentials():
    policy = load_policy(Path("config/policy.yml"))
    capability = policy.require_capability("rankings-spaces-destination")
    secret_names = {secret.public_name for secret in capability.secrets}
    assert "DIGITALOCEAN_SPACES_ACCESS_KEY_ID" not in secret_names
    assert "DIGITALOCEAN_SPACES_SECRET_ACCESS_KEY" not in secret_names
    assert secret_names == {
        "RANKINGS_SPACES_REGION",
        "RANKINGS_SPACES_ENDPOINT",
        "RANKINGS_SPACES_BUCKET",
    }

    grant = next(
        grant for grant in policy.grants if grant.description == "Sendouq ranked update workflow."
    )
    assert "digitalocean-spaces-write" in grant.capabilities
    assert "rankings-spaces-destination" in grant.capabilities


def test_postgres_read_only_exposes_connection_fields_not_urls():
    policy = load_policy(Path("config/policy.yml"))
    capability = policy.require_capability("postgres-read-only")
    secret_names = {secret.public_name for secret in capability.secrets}
    assert "RANKINGS_DATABASE_URL" not in secret_names
    assert "TEAM_SEARCH_SOURCE_DATABASE_URL" not in secret_names
    assert secret_names == {
        "POSTGRES_READ_ONLY_ACCOUNT",
        "POSTGRES_READ_ONLY_ADDRESS",
        "POSTGRES_READ_ONLY_PASSWORD",
        "POSTGRES_READ_ONLY_PORT",
        "RANKINGS_DB_SCHEMA",
    }


def test_write_postgres_capabilities_expose_connection_fields_not_urls():
    policy = load_policy(Path("config/policy.yml"))
    rankings = policy.require_capability("rankings-db-write")
    team_search = policy.require_capability("team-search-db-write")

    rankings_secret_names = {secret.public_name for secret in rankings.secrets}
    assert "RANKINGS_DATABASE_URL" not in rankings_secret_names
    assert rankings_secret_names == {
        "RANKINGS_POSTGRES_ACCOUNT",
        "RANKINGS_POSTGRES_PASSWORD",
        "RANKINGS_POSTGRES_ADDRESS",
        "RANKINGS_POSTGRES_PORT",
        "RANKINGS_POSTGRES_DATABASE",
        "RANKINGS_DB_SCHEMA",
    }

    team_search_secret_names = {secret.public_name for secret in team_search.secrets}
    assert "TEAM_SEARCH_DATABASE_URL" not in team_search_secret_names
    assert team_search_secret_names == {
        "TEAM_SEARCH_POSTGRES_ACCOUNT",
        "TEAM_SEARCH_POSTGRES_PASSWORD",
        "TEAM_SEARCH_POSTGRES_ADDRESS",
        "TEAM_SEARCH_POSTGRES_PORT",
        "TEAM_SEARCH_POSTGRES_DATABASE",
    }


def test_real_policy_standardized_secret_names():
    policy = load_policy(Path("config/policy.yml"))
    expected = {
        "digitalocean-k8s-deploy": {
            "DIGITALOCEAN_ACCESS_TOKEN",
            "DIGITALOCEAN_KUBERNETES_CLUSTER_ID",
        },
        "digitalocean-registry-write": {"DIGITALOCEAN_REGISTRY_TOKEN"},
        "sendou-api-read": {"SENDOU_API_KEY"},
        "rankings-sentry-reporting": {"RANKINGS_SENTRY_DSN"},
        "splatnet3-github-write": {"SPLATNET3_GITHUB_TOKEN"},
        "splatnet3-package-pypi-publish": {"SPLATNET3_PYPI_TOKEN"},
        "config-repo-write": {
            "GARZAI_CLUSTER_GITHUB_TOKEN",
            "SPLATTOP_CONFIG_GITHUB_TOKEN",
        },
        "digitalocean-spaces-write": {
            "DIGITALOCEAN_SPACES_ACCESS_KEY_ID",
            "DIGITALOCEAN_SPACES_SECRET_ACCESS_KEY",
        },
    }

    for capability_name, secret_names in expected.items():
        capability = policy.require_capability(capability_name)
        assert {secret.public_name for secret in capability.secrets} == secret_names


def test_agent_workloads_ci_contract_access_allows_main_and_pull_requests():
    policy = load_policy(Path("config/policy.yml"))
    base_claims = {
        "repository": "cesaregarza/agent-workloads",
        "repository_id": "1250959955",
        "repository_owner_id": "40225001",
    }

    claim_variants = [
        {
            **base_claims,
            "ref": "refs/heads/main",
            "workflow_ref": (
                "cesaregarza/agent-workloads/.github/workflows/ci.yml@refs/heads/main"
            ),
        },
        {
            **base_claims,
            "ref": "refs/pull/123/merge",
            "workflow_ref": (
                "cesaregarza/agent-workloads/.github/workflows/ci.yml@refs/pull/123/merge"
            ),
        },
    ]

    for claims in claim_variants:
        capabilities = authorize_capabilities(policy, ["mandate-contracts-read"], claims)
        assert [capability.name for capability in capabilities] == ["mandate-contracts-read"]


def test_agent_workloads_publish_access_allows_registry_and_config_repo_write():
    policy = load_policy(Path("config/policy.yml"))
    claims = {
        "repository": "cesaregarza/agent-workloads",
        "repository_id": "1250959955",
        "repository_owner_id": "40225001",
        "ref": "refs/heads/main",
        "environment": "default",
        "workflow_ref": (
            "cesaregarza/agent-workloads/.github/workflows/"
            "publish_image.yaml@refs/heads/main"
        ),
    }

    capabilities = authorize_capabilities(
        policy,
        ["digitalocean-registry-write", "config-repo-write"],
        claims,
    )

    assert [capability.name for capability in capabilities] == [
        "digitalocean-registry-write",
        "config-repo-write",
    ]


def test_config_repo_ci_gates_accept_garzaicluster_repo_name():
    policy = load_policy(Path("config/policy.yml"))

    base_claims = {
        "repository": "cesaregarza/GarzAICluster",
        "repository_id": "1094738678",
        "repository_owner_id": "40225001",
    }

    claim_variants = [
        {
            **base_claims,
            "ref": "refs/heads/main",
            "workflow_ref": (
                "cesaregarza/GarzAICluster/.github/workflows/ci.yaml@refs/heads/main"
            ),
        },
        {
            **base_claims,
            "ref": "refs/pull/123/merge",
            "workflow_ref": (
                "cesaregarza/GarzAICluster/.github/workflows/ci.yaml@refs/pull/123/merge"
            ),
        },
    ]

    for claims in claim_variants:
        capabilities = authorize_capabilities(
            policy,
            ["sops-drift-gate-decrypt", "mandate-contracts-read"],
            claims,
        )
        assert {capability.name for capability in capabilities} == {
            "mandate-contracts-read",
            "sops-drift-gate-decrypt",
        }
        secrets_by_capability = {
            capability.name: {secret.public_name for secret in capability.secrets}
            for capability in capabilities
        }
        assert secrets_by_capability["sops-drift-gate-decrypt"] == {
            "SOPS_DRIFT_GATE_AGE_KEY"
        }
        assert secrets_by_capability["mandate-contracts-read"] == {
            "MANDATE_CONTRACTS_READ_TOKEN"
        }


def test_config_repo_drift_gate_scoped_key_denies_wrong_identity():
    policy = load_policy(Path("config/policy.yml"))

    with pytest.raises(
        AuthorizationError,
        match="identity is not allowed to access credential capabilities",
    ):
        authorize_capabilities(
            policy,
            ["sops-drift-gate-decrypt"],
            {
                "repository": "cesaregarza/agent-workloads",
                "repository_id": "1250959955",
                "repository_owner_id": "40225001",
                "ref": "refs/heads/main",
                "workflow_ref": (
                    "cesaregarza/agent-workloads/.github/workflows/"
                    "publish_image.yaml@refs/heads/main"
                ),
            },
        )

    old_repo_name = "SplatTop" + "Config"
    with pytest.raises(
        AuthorizationError,
        match="identity is not allowed to access credential capabilities",
    ):
        authorize_capabilities(
            policy,
            ["sops-drift-gate-decrypt"],
            {
                "repository": f"cesaregarza/{old_repo_name}",
                "repository_id": "1094738678",
                "repository_owner_id": "40225001",
                "ref": "refs/heads/main",
                "workflow_ref": (
                    f"cesaregarza/{old_repo_name}/.github/workflows/"
                    "ci.yaml@refs/heads/main"
                ),
            },
        )


def test_citrus_private_fork_deploy_access_requires_master_ref_and_environment():
    policy = load_policy(Path("config/policy.yml"))
    base_claims = {
        "repository": "cesaregarza/Citrus",
        "repository_id": "1260019713",
        "repository_owner_id": "40225001",
        "ref": "refs/heads/master",
        "environment": "Citrus",
    }

    claim_variants = [
        {
            **base_claims,
            "workflow_ref": (
                "cesaregarza/Citrus/.github/workflows/build-deploy-citrus.yml@refs/heads/master"
            ),
        },
        {
            **base_claims,
            "job_workflow_ref": (
                "cesaregarza/Citrus/.github/workflows/build-deploy-citrus.yml@refs/heads/master"
            ),
        },
    ]

    for claims in claim_variants:
        capabilities = authorize_capabilities(
            policy,
            ["digitalocean-k8s-deploy", "config-repo-write"],
            claims,
        )
        assert [capability.name for capability in capabilities] == [
            "digitalocean-k8s-deploy",
            "config-repo-write",
        ]


@pytest.mark.parametrize("claim_name", ["workflow_ref", "job_workflow_ref"])
def test_citrus_private_fork_deploy_access_rejects_dev_branch(claim_name: str):
    policy = load_policy(Path("config/policy.yml"))

    with pytest.raises(
        AuthorizationError,
        match="identity is not allowed to access credential capabilities",
    ):
        authorize_capabilities(
            policy,
            ["digitalocean-k8s-deploy", "config-repo-write"],
            {
                "repository": "cesaregarza/Citrus",
                "repository_id": "1260019713",
                "repository_owner_id": "40225001",
                "ref": "refs/heads/codex/deploy-citrus-dev",
                "environment": "Citrus",
                claim_name: (
                    "cesaregarza/Citrus/.github/workflows/"
                    "build-deploy-citrus.yml@refs/heads/codex/deploy-citrus-dev"
                ),
            },
        )


def test_citrus_private_fork_deploy_access_rejects_missing_environment():
    policy = load_policy(Path("config/policy.yml"))

    with pytest.raises(
        AuthorizationError,
        match="identity is not allowed to access credential capabilities",
    ):
        authorize_capabilities(
            policy,
            ["digitalocean-k8s-deploy", "config-repo-write"],
            {
                "repository": "cesaregarza/Citrus",
                "repository_id": "1260019713",
                "repository_owner_id": "40225001",
                "ref": "refs/heads/master",
                "workflow_ref": (
                    "cesaregarza/Citrus/.github/workflows/"
                    "build-deploy-citrus.yml@refs/heads/master"
                ),
            },
        )


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


def test_exact_match_safety_claims_authorize(tmp_path):
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
                    event_name: workflow_dispatch
                    repository_visibility: private
                    runner_environment: github-hosted
                    job_workflow_sha: abc123
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )

    policy = load_policy(policy_path)
    authorize_capabilities(
        policy,
        ["deploy"],
        {
            "repository": "cesaregarza/SplatTop",
            "event_name": "workflow_dispatch",
            "repository_visibility": "private",
            "runner_environment": "github-hosted",
            "job_workflow_sha": "abc123",
        },
    )


def test_exact_match_safety_claim_missing_or_non_matching_denies(tmp_path):
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
                    event_name: workflow_dispatch
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )

    policy = load_policy(policy_path)
    with pytest.raises(AuthorizationError):
        authorize_capabilities(policy, ["deploy"], {"repository": "cesaregarza/SplatTop"})
    with pytest.raises(AuthorizationError):
        authorize_capabilities(
            policy,
            ["deploy"],
            {
                "repository": "cesaregarza/SplatTop",
                "event_name": "push",
            },
        )


def test_invalid_policy_rejects_safety_claim_wildcard(tmp_path):
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
                    event_name: workflow_*
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="event_name cannot use wildcards"):
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


def test_strict_object_requires_all_listed_claims(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            strict:
              required_claims:
                - repository_id
                - repository_owner_id
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                    repository_id: "12345"
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="repository_owner_id"):
        load_policy(policy_path)


def test_strict_object_accepts_all_listed_claims(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            strict:
              required_claims:
                - repository_id
                - repository_owner_id
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                    repository_id: "12345"
                    repository_owner_id: "67890"
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )

    policy = load_policy(policy_path)
    assert policy.strict is True
    assert policy.strict_required_claims == ("repository_id", "repository_owner_id")


def test_capability_required_claims_validate_referencing_grants(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                required_claims:
                  - repository_id
                  - job_workflow_ref
                secrets:
                  TOKEN:
                    env: TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                    repository_id: "12345"
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="capability deploy requires"):
        load_policy(policy_path)


def test_capability_required_claims_accept_complete_grants(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                required_claims:
                  - repository_id
                  - job_workflow_ref
                secrets:
                  TOKEN:
                    env: TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                    repository_id: "12345"
                    job_workflow_ref: org/.github/.github/workflows/deploy.yml@refs/heads/main
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )

    policy = load_policy(policy_path)
    assert policy.require_capability("deploy").required_claims == (
        "repository_id",
        "job_workflow_ref",
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
