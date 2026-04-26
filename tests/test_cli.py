from __future__ import annotations

import textwrap

import pytest

from github_credential_broker.cli import validate_policy_main


def test_validate_policy_main_accepts_valid_policy(tmp_path, capsys):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            bundles:
              deploy:
                allow:
                  - repository: cesaregarza/SplatTop
                    repository_id: "12345"
                secrets:
                  TOKEN:
                    env: TOKEN
            """
        ),
        encoding="utf-8",
    )

    validate_policy_main([str(policy_path)])

    captured = capsys.readouterr()
    assert "policy valid" in captured.out


def test_validate_policy_main_rejects_invalid_policy(tmp_path, capsys):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text("version: 2\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        validate_policy_main([str(policy_path)])

    captured = capsys.readouterr()
    assert exc_info.value.code == 1
    assert "policy invalid" in captured.err
