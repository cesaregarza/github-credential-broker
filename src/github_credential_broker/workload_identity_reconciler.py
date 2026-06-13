from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import yaml

DIGEST_SPEC_VERSION = "agent-workloads-code-digest-v1"
DIGEST_SPEC_VERSION_FILE = "DIGEST_SPEC_VERSION"
DIGEST_SPEC_DOC = "docs/digest-spec.md"
VALUES_PATH = Path("apps/agent-workloads/values.yaml")
OVERLAY_CONFIGMAP_PATH = Path("apps/agent-control-plane-registry-overlay/configmap.yaml")
TOKEN_METADATA_PATH = Path("secrets/agent-workloads/workload-identity-tokens.metadata.yaml")
EXPECTED_AGENT_IDS = (
    "data.workspace_probe",
    "opencode.apply_executor",
    "opencode.proposer",
)
EXPECTED_DIGEST_RELATIVE_FILES = ("pyproject.toml", "uv.lock")
EXPECTED_DIGEST_SHARED_DIRS = ("src",)
CODE_DIGEST_EXCLUDED_DIR_NAMES = frozenset({"__pycache__"})
CODE_DIGEST_EXCLUDED_DIR_SUFFIXES = (".egg-info",)
ALLOWED_REPIN_PATHS = frozenset(
    {
        VALUES_PATH.as_posix(),
        OVERLAY_CONFIGMAP_PATH.as_posix(),
        "secrets/agent-workloads/workload-identity-tokens.enc.yaml",
        TOKEN_METADATA_PATH.as_posix(),
    }
)
SHA_RE = re.compile(r"^[a-f0-9]{7,40}$")
SHA256_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
REPIN_BRANCH_RE = re.compile(r"^bot/agent-workloads-release-[a-f0-9]{7,40}$")
ROLLBACK_APPROVED_LABEL = "rollback-approved"


class ReconcilerError(ValueError):
    """Raised when workload identity reconciliation input is malformed."""


@dataclass(frozen=True)
class DigestEntry:
    relpath: str
    data: bytes


@dataclass(frozen=True)
class ReleasePin:
    code_digest: str
    manifest_digest: str
    image_digest: str

    def to_dict(self) -> dict[str, str]:
        return {
            "code_digest": self.code_digest,
            "manifest_digest": self.manifest_digest,
            "image_digest": self.image_digest,
        }


@dataclass(frozen=True)
class WorkloadMintDryRun:
    agent_id: str
    code_digest: str
    manifest_digest: str
    image_digest: str
    source_commit: str
    digest_spec_version: str

    def to_dict(self) -> dict[str, str]:
        return {
            "agent_id": self.agent_id,
            "code_digest": self.code_digest,
            "manifest_digest": self.manifest_digest,
            "image_digest": self.image_digest,
            "source_commit": self.source_commit,
            "digest_spec_version": self.digest_spec_version,
        }


@dataclass(frozen=True)
class ReconcileDecision:
    status: Literal["ignored", "refused", "would_mint"]
    reason: str
    message: str
    source_commit: str | None
    head_ref: str
    changed_paths: tuple[str, ...]
    workloads: tuple[WorkloadMintDryRun, ...] = ()
    violations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "message": self.message,
            "source_commit": self.source_commit,
            "head_ref": self.head_ref,
            "changed_paths": list(self.changed_paths),
            "workloads": [workload.to_dict() for workload in self.workloads],
            "violations": list(self.violations),
        }


def evaluate_repin_pr(
    *,
    splattop_config_root: Path,
    agent_workloads_tarball: Path,
    head_ref: str,
    changed_paths: Iterable[str],
    source_commit: str,
    agent_workloads_main_head: str,
    labels: Iterable[str] = (),
) -> ReconcileDecision:
    """Return a read-only workload identity mint decision for one re-pin PR.

    This function intentionally does not read secrets, decrypt SOPS files, mint tokens,
    or push commits. It validates whether a future mint step would have enough
    trusted, self-consistent deployment data to mint.
    """

    normalized_paths = tuple(sorted({_normalize_repo_path(path) for path in changed_paths}))
    normalized_labels = frozenset(label.strip().lower() for label in labels if label.strip())
    try:
        _validate_sha(source_commit, "source_commit")
        _validate_sha(agent_workloads_main_head, "agent_workloads_main_head")
    except ReconcilerError as exc:
        return _refused(
            reason="invalid_commit",
            message=str(exc),
            head_ref=head_ref,
            source_commit=source_commit,
            changed_paths=normalized_paths,
        )

    if REPIN_BRANCH_RE.fullmatch(head_ref) is None:
        return ReconcileDecision(
            status="ignored",
            reason="not_repin_branch",
            message="head ref is not a bot/agent-workloads-release-* re-pin branch",
            source_commit=source_commit,
            head_ref=head_ref,
            changed_paths=normalized_paths,
        )

    path_violations = _path_violations(normalized_paths)
    if path_violations:
        return _refused(
            reason="forbidden_path",
            message="re-pin PR touches forbidden or non-allowlisted paths",
            head_ref=head_ref,
            source_commit=source_commit,
            changed_paths=normalized_paths,
            violations=path_violations,
        )

    if (
        source_commit != agent_workloads_main_head
        and ROLLBACK_APPROVED_LABEL not in normalized_labels
    ):
        return _refused(
            reason="source_commit_not_main_head",
            message=(
                "source commit must equal protected agent-workloads main HEAD unless "
                "rollback-approved is present"
            ),
            head_ref=head_ref,
            source_commit=source_commit,
            changed_paths=normalized_paths,
            violations=(
                f"source_commit={source_commit}",
                f"agent_workloads_main_head={agent_workloads_main_head}",
            ),
        )

    try:
        release_pins = load_release_pins(splattop_config_root / VALUES_PATH)
        overlay_pins = load_overlay_pins(splattop_config_root / OVERLAY_CONFIGMAP_PATH)
        metadata_pins = load_metadata_pins(splattop_config_root / TOKEN_METADATA_PATH)
        tarball_code_digests = tarball_agent_code_digests(agent_workloads_tarball)
    except ReconcilerError as exc:
        return _refused(
            reason="invalid_input",
            message=str(exc),
            head_ref=head_ref,
            source_commit=source_commit,
            changed_paths=normalized_paths,
        )

    violations = _pin_violations(
        release_pins=release_pins,
        overlay_pins=overlay_pins,
        metadata_pins=metadata_pins,
        tarball_code_digests=tarball_code_digests,
        source_commit=source_commit,
    )
    if violations:
        return _refused(
            reason="pin_mismatch",
            message="release pins, overlay manifests, metadata ledger, and tarball digests differ",
            head_ref=head_ref,
            source_commit=source_commit,
            changed_paths=normalized_paths,
            violations=violations,
        )

    workloads = tuple(
        WorkloadMintDryRun(
            agent_id=agent_id,
            code_digest=release_pins[agent_id].code_digest,
            manifest_digest=release_pins[agent_id].manifest_digest,
            image_digest=release_pins[agent_id].image_digest,
            source_commit=source_commit,
            digest_spec_version=DIGEST_SPEC_VERSION,
        )
        for agent_id in EXPECTED_AGENT_IDS
    )
    return ReconcileDecision(
        status="would_mint",
        reason="ok",
        message=(
            "re-pin PR is eligible for the future mint step; this dry-run did not mint "
            "or read secret material"
        ),
        source_commit=source_commit,
        head_ref=head_ref,
        changed_paths=normalized_paths,
        workloads=workloads,
    )


def load_release_pins(values_path: Path) -> dict[str, ReleasePin]:
    values = _load_yaml(values_path)
    pins = values.get("mandateReleasePins")
    if not isinstance(pins, dict):
        raise ReconcilerError("apps/agent-workloads/values.yaml missing mandateReleasePins")
    return _release_pins_from_mapping(pins, label="mandateReleasePins")


def load_overlay_pins(configmap_path: Path) -> dict[str, ReleasePin]:
    configmap = _load_yaml(configmap_path)
    data = configmap.get("data")
    if not isinstance(data, dict):
        raise ReconcilerError("registry overlay ConfigMap missing data mapping")
    imports = yaml.safe_load(data.get("workload_imports.yaml") or "")
    if not isinstance(imports, dict) or not isinstance(imports.get("imports"), list):
        raise ReconcilerError("registry overlay workload_imports.yaml missing imports list")

    pins: dict[str, ReleasePin] = {}
    for entry in imports["imports"]:
        if not isinstance(entry, dict):
            raise ReconcilerError("registry overlay import entries must be mappings")
        agent_id = _required_str(entry, "id", "workload import")
        if agent_id not in EXPECTED_AGENT_IDS:
            continue
        manifest_path = Path(_required_str(entry, "manifest_path", agent_id))
        manifest_raw = data.get(manifest_path.name)
        if not isinstance(manifest_raw, str):
            raise ReconcilerError(f"registry overlay missing embedded manifest: {agent_id}")
        manifest = json.loads(manifest_raw)
        if not isinstance(manifest, dict):
            raise ReconcilerError(f"embedded manifest must be a mapping: {agent_id}")
        image = manifest.get("image")
        if not isinstance(image, dict):
            raise ReconcilerError(f"embedded manifest image must be a mapping: {agent_id}")
        pin = ReleasePin(
            code_digest=_required_digest(manifest, "code_digest", agent_id),
            manifest_digest=_required_digest(manifest, "digest", agent_id),
            image_digest=_required_digest(image, "digest", agent_id),
        )
        if entry.get("manifest_digest") != pin.manifest_digest:
            raise ReconcilerError(f"{agent_id} import manifest_digest differs from manifest")
        if entry.get("image_digest") != pin.image_digest:
            raise ReconcilerError(f"{agent_id} import image_digest differs from manifest")
        pins[agent_id] = pin
    _assert_expected_agents(pins, "registry overlay")
    return pins


def load_metadata_pins(metadata_path: Path) -> dict[str, dict[str, str]]:
    metadata = _load_yaml(metadata_path)
    tokens = metadata.get("tokens")
    if not isinstance(tokens, dict):
        raise ReconcilerError("workload identity metadata missing tokens mapping")
    _assert_expected_agents(tokens, "workload identity metadata")
    pins: dict[str, dict[str, str]] = {}
    for agent_id in EXPECTED_AGENT_IDS:
        entry = tokens[agent_id]
        if not isinstance(entry, dict):
            raise ReconcilerError(f"metadata entry must be a mapping: {agent_id}")
        pins[agent_id] = {
            "code_digest": _required_digest(entry, "code_digest", agent_id),
            "manifest_digest": _required_digest(entry, "manifest_digest", agent_id),
            "source_commit": _required_str(entry, "source_commit", agent_id),
        }
    return pins


def tarball_agent_code_digests(tarball_path: Path) -> dict[str, str]:
    entries = _read_tarball_regular_entries(tarball_path)
    _assert_tarball_spec_version(entries)
    digests: dict[str, str] = {}
    for relpath in sorted(entries):
        path = PurePosixPath(relpath)
        if len(path.parts) != 3 or path.parts[0] != "agents" or path.parts[2] != "agent.yaml":
            continue
        descriptor = yaml.safe_load(entries[relpath].decode("utf-8"))
        if not isinstance(descriptor, dict):
            raise ReconcilerError(f"agent descriptor must be a mapping: {relpath}")
        agent_id = descriptor.get("id")
        if not isinstance(agent_id, str) or not agent_id:
            raise ReconcilerError(f"agent descriptor missing id: {relpath}")
        digests[agent_id] = _digest_entries(
            DigestEntry(relpath=item, data=entries[item])
            for item in _tarball_digest_relpaths(relpath, entries)
        )
    _assert_expected_agents(digests, "agent-workloads tarball")
    return digests


def _pin_violations(
    *,
    release_pins: Mapping[str, ReleasePin],
    overlay_pins: Mapping[str, ReleasePin],
    metadata_pins: Mapping[str, Mapping[str, str]],
    tarball_code_digests: Mapping[str, str],
    source_commit: str,
) -> tuple[str, ...]:
    violations: list[str] = []
    for agent_id in EXPECTED_AGENT_IDS:
        release = release_pins[agent_id]
        overlay = overlay_pins[agent_id]
        metadata = metadata_pins[agent_id]
        tarball_code_digest = tarball_code_digests[agent_id]
        if release != overlay:
            violations.append(f"{agent_id}: mandateReleasePins differs from registry overlay")
        if release.code_digest != metadata["code_digest"]:
            violations.append(f"{agent_id}: metadata code_digest differs from release pin")
        if release.manifest_digest != metadata["manifest_digest"]:
            violations.append(f"{agent_id}: metadata manifest_digest differs from release pin")
        if metadata["source_commit"] != source_commit:
            violations.append(f"{agent_id}: metadata source_commit differs from PR source commit")
        if release.code_digest != tarball_code_digest:
            violations.append(f"{agent_id}: release codeDigest differs from tarball digest")
    return tuple(violations)


def _release_pins_from_mapping(raw_pins: Mapping[str, Any], *, label: str) -> dict[str, ReleasePin]:
    _assert_expected_agents(raw_pins, label)
    pins: dict[str, ReleasePin] = {}
    for agent_id in EXPECTED_AGENT_IDS:
        raw = raw_pins[agent_id]
        if not isinstance(raw, dict):
            raise ReconcilerError(f"{label}.{agent_id} must be a mapping")
        pins[agent_id] = ReleasePin(
            code_digest=_required_digest(raw, "codeDigest", agent_id),
            manifest_digest=_required_digest(raw, "manifestDigest", agent_id),
            image_digest=_required_digest(raw, "imageDigest", agent_id),
        )
    return pins


def _tarball_digest_relpaths(
    descriptor_relpath: str,
    entries: Mapping[str, bytes],
) -> tuple[str, ...]:
    _validate_relpath(descriptor_relpath)
    if descriptor_relpath not in entries:
        raise ReconcilerError(f"agent descriptor missing from tarball: {descriptor_relpath}")
    relpaths = {descriptor_relpath}
    for relpath in EXPECTED_DIGEST_RELATIVE_FILES:
        if relpath not in entries:
            raise ReconcilerError(f"required digest file missing from tarball: {relpath}")
        relpaths.add(relpath)
    for relpath in entries:
        if any(
            relpath == shared_dir or relpath.startswith(f"{shared_dir}/")
            for shared_dir in EXPECTED_DIGEST_SHARED_DIRS
        ) and _include_in_code_digest(relpath):
            relpaths.add(relpath)
    return tuple(sorted(relpaths))


def _digest_entries(entries: Iterable[DigestEntry]) -> str:
    digest = hashlib.sha256()
    normalized: list[tuple[str, bytes, bytes]] = []
    seen: set[str] = set()
    for entry in entries:
        relpath_bytes = _validate_relpath(entry.relpath)
        if entry.relpath in seen:
            raise ReconcilerError(f"duplicate digest path: {entry.relpath}")
        seen.add(entry.relpath)
        normalized.append((entry.relpath, relpath_bytes, entry.data))
    for _relpath, relpath_bytes, data in sorted(normalized, key=lambda item: item[0]):
        digest.update(relpath_bytes)
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return f"sha256:{digest.hexdigest()}"


def _read_tarball_regular_entries(tarball_path: Path) -> dict[str, bytes]:
    entries: dict[str, bytes] = {}
    try:
        with tarfile.open(tarball_path, mode="r:*") as archive:
            prefix = _tarball_prefix(archive.getnames())
            for member in archive.getmembers():
                relpath = _strip_tarball_prefix(member.name, prefix)
                if relpath is None or member.isdir():
                    continue
                if _is_relevant_digest_path(relpath):
                    if member.issym():
                        raise ReconcilerError(f"symlink is forbidden in tarball: {relpath}")
                    if member.islnk():
                        raise ReconcilerError(f"hard link is forbidden in tarball: {relpath}")
                    if not member.isfile():
                        raise ReconcilerError(
                            f"non-regular file is forbidden in tarball: {relpath}"
                        )
                if not member.isfile():
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ReconcilerError(f"tarball member could not be read: {relpath}")
                if relpath in entries:
                    raise ReconcilerError(f"duplicate tarball path: {relpath}")
                entries[relpath] = extracted.read()
    except tarfile.TarError as exc:
        raise ReconcilerError(f"could not open agent-workloads tarball: {tarball_path}") from exc
    _assert_no_export_filters(entries.get(".gitattributes", b""), source=".gitattributes")
    return entries


def _assert_tarball_spec_version(entries: Mapping[str, bytes]) -> None:
    raw = entries.get(DIGEST_SPEC_VERSION_FILE)
    if raw is None:
        raise ReconcilerError(f"tarball missing {DIGEST_SPEC_VERSION_FILE}")
    declared = raw.decode("utf-8").strip()
    if declared != DIGEST_SPEC_VERSION:
        raise ReconcilerError(
            f"tarball declares {declared!r}, tool implements {DIGEST_SPEC_VERSION!r}"
        )
    doc = entries.get(DIGEST_SPEC_DOC)
    if doc is None or DIGEST_SPEC_VERSION not in doc.decode("utf-8", errors="replace"):
        raise ReconcilerError(f"tarball {DIGEST_SPEC_DOC} must mention {DIGEST_SPEC_VERSION}")


def _tarball_prefix(names: Iterable[str]) -> str:
    prefixes = {
        PurePosixPath(name).parts[0]
        for name in names
        if PurePosixPath(name).parts
    }
    if len(prefixes) != 1:
        raise ReconcilerError(f"tarball must contain exactly one root prefix: {sorted(prefixes)}")
    return next(iter(prefixes))


def _strip_tarball_prefix(name: str, prefix: str) -> str | None:
    _validate_relpath(name)
    parts = PurePosixPath(name).parts
    if not parts or parts[0] != prefix:
        raise ReconcilerError(f"tarball path outside prefix {prefix}: {name}")
    if len(parts) == 1:
        return None
    return _validate_relpath_to_str(PurePosixPath(*parts[1:]).as_posix())


def _is_relevant_digest_path(relpath: str) -> bool:
    if relpath in EXPECTED_DIGEST_RELATIVE_FILES:
        return True
    if relpath == "src" or relpath.startswith("src/"):
        return _include_in_code_digest(relpath)
    path = PurePosixPath(relpath)
    return len(path.parts) == 3 and path.parts[0] == "agents" and path.parts[2] == "agent.yaml"


def _include_in_code_digest(relpath: str | Path) -> bool:
    path = PurePosixPath(relpath.as_posix() if isinstance(relpath, Path) else relpath)
    return not any(
        part in CODE_DIGEST_EXCLUDED_DIR_NAMES
        or part.endswith(CODE_DIGEST_EXCLUDED_DIR_SUFFIXES)
        for part in path.parts
    )


def _assert_no_export_filters(raw: bytes, *, source: str) -> None:
    if not raw:
        return
    text = raw.decode("utf-8")
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "export-ignore" in stripped or "export-subst" in stripped:
            raise ReconcilerError(
                f"{source}:{line_number} uses forbidden export filter in digest input"
            )


def _path_violations(paths: Sequence[str]) -> tuple[str, ...]:
    violations: list[str] = []
    for path in paths:
        if path == ".sops.yaml":
            violations.append(".sops.yaml changes cannot receive freshly minted tokens")
        elif path not in ALLOWED_REPIN_PATHS:
            violations.append(f"non-allowlisted re-pin path: {path}")
    return tuple(violations)


def _normalize_repo_path(path: str) -> str:
    value = path.strip()
    _validate_relpath(value)
    return value


def _validate_sha(raw: str, label: str) -> None:
    if SHA_RE.fullmatch(raw) is None:
        raise ReconcilerError(f"{label} must be 7-40 lowercase hex characters")


def _validate_relpath_to_str(relpath: str) -> str:
    _validate_relpath(relpath)
    return relpath


def _validate_relpath(relpath: str) -> bytes:
    try:
        encoded = relpath.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ReconcilerError(f"path is not valid UTF-8: {relpath!r}") from exc
    path = PurePosixPath(relpath)
    if path.is_absolute():
        raise ReconcilerError(f"path must be relative: {relpath}")
    if not path.parts:
        raise ReconcilerError("path must not be empty")
    if any(part in {"", ".."} for part in path.parts):
        raise ReconcilerError(f"path must not contain empty or '..': {relpath}")
    return encoded


def _assert_expected_agents(mapping: Mapping[str, Any], label: str) -> None:
    expected = set(EXPECTED_AGENT_IDS)
    actual = set(mapping)
    if actual != expected:
        raise ReconcilerError(
            f"{label} must cover exactly {', '.join(EXPECTED_AGENT_IDS)}; "
            f"got {', '.join(sorted(actual))}"
        )


def _required_str(mapping: Mapping[str, Any], key: str, label: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise ReconcilerError(f"{label} missing non-empty {key}")
    return value


def _required_digest(mapping: Mapping[str, Any], key: str, label: str) -> str:
    value = _required_str(mapping, key, label)
    if SHA256_DIGEST_RE.fullmatch(value) is None:
        raise ReconcilerError(f"{label}.{key} must be sha256:<64 lowercase hex>")
    return value


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ReconcilerError(f"could not read YAML: {path}") from exc
    if not isinstance(loaded, dict):
        raise ReconcilerError(f"YAML mapping expected: {path}")
    return loaded


def _refused(
    *,
    reason: str,
    message: str,
    head_ref: str,
    source_commit: str | None,
    changed_paths: tuple[str, ...],
    violations: tuple[str, ...] = (),
) -> ReconcileDecision:
    return ReconcileDecision(
        status="refused",
        reason=reason,
        message=message,
        source_commit=source_commit,
        head_ref=head_ref,
        changed_paths=changed_paths,
        violations=violations,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Dry-run the agent-workloads workload identity reconciler for one "
            "SplatTopConfig re-pin branch. This command does not mint or read secrets."
        )
    )
    parser.add_argument("--splattop-config-repo", type=Path, required=True)
    parser.add_argument("--agent-workloads-tarball", type=Path, required=True)
    parser.add_argument("--head-ref", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--agent-workloads-main-head", required=True)
    parser.add_argument("--changed-path", action="append", default=[])
    parser.add_argument("--label", action="append", default=[])
    parser.add_argument(
        "--fail-on-refusal",
        action="store_true",
        help="exit non-zero when the dry-run refuses the re-pin PR",
    )
    args = parser.parse_args(argv)

    decision = evaluate_repin_pr(
        splattop_config_root=args.splattop_config_repo,
        agent_workloads_tarball=args.agent_workloads_tarball,
        head_ref=args.head_ref,
        changed_paths=args.changed_path,
        source_commit=args.source_commit,
        agent_workloads_main_head=args.agent_workloads_main_head,
        labels=args.label,
    )
    print(json.dumps(decision.to_dict(), indent=2, sort_keys=True))
    if args.fail_on_refusal and decision.status == "refused":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
