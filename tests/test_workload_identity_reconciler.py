from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path

import pytest
import yaml

from github_credential_broker.workload_identity_reconciler import (
    DIGEST_SPEC_VERSION,
    OVERLAY_CONFIGMAP_PATH,
    TOKEN_METADATA_PATH,
    VALUES_PATH,
    evaluate_repin_pr,
    main,
    tarball_agent_code_digests,
)

SOURCE_COMMIT = "a1fb3e2c7a04"
HEAD_REF = f"bot/agent-workloads-release-{SOURCE_COMMIT}"


def test_reconciler_would_mint_for_consistent_repin_fixture(tmp_path: Path) -> None:
    fixture = _write_fixture(tmp_path)

    decision = evaluate_repin_pr(
        splattop_config_root=fixture.config_root,
        agent_workloads_tarball=fixture.tarball,
        head_ref=HEAD_REF,
        changed_paths=[
            VALUES_PATH.as_posix(),
            OVERLAY_CONFIGMAP_PATH.as_posix(),
        ],
        source_commit=SOURCE_COMMIT,
        agent_workloads_main_head=SOURCE_COMMIT,
    )

    assert decision.status == "would_mint"
    assert decision.reason == "ok"
    assert [workload.agent_id for workload in decision.workloads] == [
        "data.workspace_probe",
        "opencode.apply_executor",
        "opencode.proposer",
    ]
    assert all(workload.source_commit == SOURCE_COMMIT for workload in decision.workloads)
    assert all(
        workload.digest_spec_version == DIGEST_SPEC_VERSION for workload in decision.workloads
    )


def test_reconciler_does_not_read_encrypted_token_file_in_dry_run(tmp_path: Path) -> None:
    fixture = _write_fixture(tmp_path)

    decision = evaluate_repin_pr(
        splattop_config_root=fixture.config_root,
        agent_workloads_tarball=fixture.tarball,
        head_ref=HEAD_REF,
        changed_paths=[
            "secrets/agent-workloads/workload-identity-tokens.enc.yaml",
            TOKEN_METADATA_PATH.as_posix(),
        ],
        source_commit=SOURCE_COMMIT,
        agent_workloads_main_head=SOURCE_COMMIT,
    )

    assert decision.status == "would_mint"


def test_reconciler_refuses_stale_source_commit_without_rollback_label(tmp_path: Path) -> None:
    fixture = _write_fixture(tmp_path)

    decision = evaluate_repin_pr(
        splattop_config_root=fixture.config_root,
        agent_workloads_tarball=fixture.tarball,
        head_ref=HEAD_REF,
        changed_paths=[VALUES_PATH.as_posix()],
        source_commit=SOURCE_COMMIT,
        agent_workloads_main_head="bbbbbbbbbbbb",
    )

    assert decision.status == "refused"
    assert decision.reason == "source_commit_not_main_head"
    assert any("agent_workloads_main_head=bbbbbbbbbbbb" in item for item in decision.violations)


def test_reconciler_refuses_sops_yaml_changes(tmp_path: Path) -> None:
    fixture = _write_fixture(tmp_path)

    decision = evaluate_repin_pr(
        splattop_config_root=fixture.config_root,
        agent_workloads_tarball=fixture.tarball,
        head_ref=HEAD_REF,
        changed_paths=[VALUES_PATH.as_posix(), ".sops.yaml"],
        source_commit=SOURCE_COMMIT,
        agent_workloads_main_head=SOURCE_COMMIT,
    )

    assert decision.status == "refused"
    assert decision.reason == "forbidden_path"
    assert decision.violations == (".sops.yaml changes cannot receive freshly minted tokens",)


def test_reconciler_refuses_non_allowlisted_paths(tmp_path: Path) -> None:
    fixture = _write_fixture(tmp_path)

    decision = evaluate_repin_pr(
        splattop_config_root=fixture.config_root,
        agent_workloads_tarball=fixture.tarball,
        head_ref=HEAD_REF,
        changed_paths=["README.md"],
        source_commit=SOURCE_COMMIT,
        agent_workloads_main_head=SOURCE_COMMIT,
    )

    assert decision.status == "refused"
    assert decision.reason == "forbidden_path"
    assert decision.violations == ("non-allowlisted re-pin path: README.md",)


def test_reconciler_refuses_pin_mismatch(tmp_path: Path) -> None:
    fixture = _write_fixture(tmp_path)
    values_path = fixture.config_root / VALUES_PATH
    values = yaml.safe_load(values_path.read_text(encoding="utf-8"))
    values["mandateReleasePins"]["opencode.proposer"]["codeDigest"] = _digest("wrong-code")
    values_path.write_text(yaml.safe_dump(values, sort_keys=False), encoding="utf-8")

    decision = evaluate_repin_pr(
        splattop_config_root=fixture.config_root,
        agent_workloads_tarball=fixture.tarball,
        head_ref=HEAD_REF,
        changed_paths=[VALUES_PATH.as_posix()],
        source_commit=SOURCE_COMMIT,
        agent_workloads_main_head=SOURCE_COMMIT,
    )

    assert decision.status == "refused"
    assert decision.reason == "pin_mismatch"
    assert any("opencode.proposer" in item for item in decision.violations)


def test_reconciler_refuses_digest_spec_mismatch(tmp_path: Path) -> None:
    fixture = _write_fixture(tmp_path)
    _write_agent_workloads_tarball(
        fixture.tarball,
        overrides={"DIGEST_SPEC_VERSION": b"agent-workloads-code-digest-v0\n"},
    )

    decision = evaluate_repin_pr(
        splattop_config_root=fixture.config_root,
        agent_workloads_tarball=fixture.tarball,
        head_ref=HEAD_REF,
        changed_paths=[VALUES_PATH.as_posix()],
        source_commit=SOURCE_COMMIT,
        agent_workloads_main_head=SOURCE_COMMIT,
    )

    assert decision.status == "refused"
    assert decision.reason == "invalid_input"
    assert "tool implements" in decision.message


def test_reconciler_ignores_non_repin_branch(tmp_path: Path) -> None:
    fixture = _write_fixture(tmp_path)

    decision = evaluate_repin_pr(
        splattop_config_root=fixture.config_root,
        agent_workloads_tarball=fixture.tarball,
        head_ref="codex/random-change",
        changed_paths=[VALUES_PATH.as_posix()],
        source_commit=SOURCE_COMMIT,
        agent_workloads_main_head=SOURCE_COMMIT,
    )

    assert decision.status == "ignored"
    assert decision.reason == "not_repin_branch"


def test_reconciler_cli_prints_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    fixture = _write_fixture(tmp_path)

    result = main(
        [
            "--splattop-config-repo",
            str(fixture.config_root),
            "--agent-workloads-tarball",
            str(fixture.tarball),
            "--head-ref",
            HEAD_REF,
            "--source-commit",
            SOURCE_COMMIT,
            "--agent-workloads-main-head",
            SOURCE_COMMIT,
            "--changed-path",
            VALUES_PATH.as_posix(),
        ]
    )

    captured = capsys.readouterr()
    assert result == 0
    rendered = json.loads(captured.out)
    assert rendered["status"] == "would_mint"
    assert rendered["workloads"][0]["digest_spec_version"] == DIGEST_SPEC_VERSION


def test_reconciler_cli_can_fail_on_refusal(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = _write_fixture(tmp_path)

    result = main(
        [
            "--splattop-config-repo",
            str(fixture.config_root),
            "--agent-workloads-tarball",
            str(fixture.tarball),
            "--head-ref",
            HEAD_REF,
            "--source-commit",
            SOURCE_COMMIT,
            "--agent-workloads-main-head",
            "bbbbbbbbbbbb",
            "--changed-path",
            VALUES_PATH.as_posix(),
            "--fail-on-refusal",
        ]
    )

    captured = capsys.readouterr()
    assert result == 1
    assert json.loads(captured.out)["reason"] == "source_commit_not_main_head"


class _Fixture:
    def __init__(self, *, config_root: Path, tarball: Path) -> None:
        self.config_root = config_root
        self.tarball = tarball


def _write_fixture(
    tmp_path: Path,
    *,
    tarball_overrides: dict[str, bytes] | None = None,
) -> _Fixture:
    tarball = tmp_path / "agent-workloads.tar.gz"
    _write_agent_workloads_tarball(tarball, overrides=tarball_overrides)
    code_digests = tarball_agent_code_digests(tarball)
    pins = {
        agent_id: {
            "codeDigest": code_digests[agent_id],
            "manifestDigest": _digest(f"{agent_id}:manifest"),
            "imageDigest": _digest(f"{agent_id}:image"),
        }
        for agent_id in sorted(code_digests)
    }

    config_root = tmp_path / "SplatTopConfig"
    (config_root / VALUES_PATH.parent).mkdir(parents=True)
    (config_root / VALUES_PATH).write_text(
        yaml.safe_dump({"mandateReleasePins": pins}, sort_keys=False),
        encoding="utf-8",
    )
    _write_registry_overlay(config_root, pins)
    _write_token_metadata(config_root, pins)
    return _Fixture(config_root=config_root, tarball=tarball)


def _write_registry_overlay(config_root: Path, pins: dict[str, dict[str, str]]) -> None:
    embedded_manifests = {}
    imports = []
    for agent_id, pin in sorted(pins.items()):
        manifest_name = f"agent-{agent_id}.json"
        manifest = {
            "digest": pin["manifestDigest"],
            "code_digest": pin["codeDigest"],
            "image": {"digest": pin["imageDigest"]},
        }
        embedded_manifests[manifest_name] = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        imports.append(
            {
                "id": agent_id,
                "manifest_path": f"registries/imports/{manifest_name}",
                "manifest_digest": pin["manifestDigest"],
                "image_digest": pin["imageDigest"],
            }
        )
    configmap = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "data": {
            "workload_imports.yaml": yaml.safe_dump(
                {"schema_version": "workload-imports.v1", "imports": imports},
                sort_keys=False,
            ),
            **embedded_manifests,
        },
    }
    path = config_root / OVERLAY_CONFIGMAP_PATH
    path.parent.mkdir(parents=True)
    path.write_text(yaml.safe_dump(configmap, sort_keys=False), encoding="utf-8")


def _write_token_metadata(config_root: Path, pins: dict[str, dict[str, str]]) -> None:
    tokens = {}
    for agent_id, pin in sorted(pins.items()):
        tokens[agent_id] = {
            "agent_id": agent_id,
            "code_digest": pin["codeDigest"],
            "manifest_digest": pin["manifestDigest"],
            "source_commit": SOURCE_COMMIT,
        }
    metadata = {
        "schema_version": "agent-workloads-workload-identity-tokens.metadata.v1",
        "tokens": tokens,
    }
    path = config_root / TOKEN_METADATA_PATH
    path.parent.mkdir(parents=True)
    path.write_text(yaml.safe_dump(metadata, sort_keys=False), encoding="utf-8")


def _write_agent_workloads_tarball(
    tarball: Path,
    *,
    overrides: dict[str, bytes] | None = None,
) -> None:
    overrides = overrides or {}
    files = {
        "DIGEST_SPEC_VERSION": f"{DIGEST_SPEC_VERSION}\n".encode(),
        "docs/digest-spec.md": f"# Digest spec\n\nVersion: {DIGEST_SPEC_VERSION}\n".encode(),
        "pyproject.toml": b"[project]\nname = 'agent-workloads'\n",
        "uv.lock": b"version = 1\n",
        "src/agent_workloads/__init__.py": b"VALUE = 'shared'\n",
        "agents/db-workspace-probe/agent.yaml": b"id: data.workspace_probe\n",
        "agents/opencode-apply-executor/agent.yaml": b"id: opencode.apply_executor\n",
        "agents/opencode-proposer/agent.yaml": b"id: opencode.proposer\n",
    }
    with tarfile.open(tarball, "w:gz") as archive:
        for relpath, default_data in files.items():
            data = overrides.get(relpath, default_data)
            info = tarfile.TarInfo(f"agent-workloads-{SOURCE_COMMIT}/{relpath}")
            info.size = len(data)
            info.mtime = 0
            archive.addfile(info, fileobj=_Bytes(data))


def _digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode()).hexdigest()}"


class _Bytes:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = len(self._data) - self._offset
        end = min(self._offset + size, len(self._data))
        chunk = self._data[self._offset : end]
        self._offset = end
        return chunk
