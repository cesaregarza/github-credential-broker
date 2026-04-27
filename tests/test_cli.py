from __future__ import annotations

import textwrap

import pytest

from github_credential_broker.cli import lint_policy_main, validate_policy_main


def test_validate_policy_main_accepts_valid_policy(tmp_path, capsys):
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
                    repository_id: "12345"
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )

    validate_policy_main([str(policy_path)])

    captured = capsys.readouterr()
    assert "policy valid" in captured.out
    assert "(1 capabilities, 1 grants)" in captured.out


def test_validate_policy_main_rejects_invalid_policy(tmp_path, capsys):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text("version: 2\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        validate_policy_main([str(policy_path)])

    captured = capsys.readouterr()
    assert exc_info.value.code == 1
    assert "policy invalid" in captured.err


def test_lint_policy_main_accepts_clean_policy(tmp_path, capsys):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                description: Production deploy token.
                secrets:
                  TOKEN:
                    env: TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                    repository_id: "12345"
                    repository_owner_id: "67890"
                    ref: refs/heads/main
                    environment: production
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )

    lint_policy_main([str(policy_path)])

    captured = capsys.readouterr()
    assert "policy lint clean" in captured.out


def test_lint_policy_main_warns_without_failing_by_default(tmp_path, capsys):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                description: Production deploy token.
                secrets:
                  TOKEN:
                    env: TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                    ref: refs/heads/*
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )

    lint_policy_main([str(policy_path)])

    captured = capsys.readouterr()
    assert "policy lint warnings" in captured.out
    assert "missing stable repository_id" in captured.out
    assert "missing stable repository_owner_id" in captured.out
    assert "without environment" in captured.out
    assert "ref uses a wildcard" in captured.out


def test_lint_policy_main_strict_fails_on_warnings(tmp_path, capsys):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                description: Production deploy token.
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

    with pytest.raises(SystemExit) as exc_info:
        lint_policy_main([str(policy_path), "--strict"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 1
    assert "policy lint warnings" in captured.out


def test_lint_policy_main_warns_on_shared_onepassword_item(tmp_path, capsys):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              app-token:
                secrets:
                  APP_TOKEN:
                    op: op://broker/shared-token/APP_TOKEN
              worker-token:
                secrets:
                  WORKER_TOKEN:
                    op: op://broker/shared-token/WORKER_TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                    repository_id: "12345"
                    repository_owner_id: "67890"
                    ref: refs/heads/main
                capabilities: [app-token, worker-token]
            """
        ),
        encoding="utf-8",
    )

    lint_policy_main([str(policy_path)])

    captured = capsys.readouterr()
    assert "share 1Password item" in captured.out
    assert "app-token, worker-token" in captured.out
