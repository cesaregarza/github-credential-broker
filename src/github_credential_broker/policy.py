from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from github_credential_broker.errors import AuthorizationError, ConfigurationError

_BUNDLE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
_CLAIM_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SECRET_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_GLOB_ALLOWED_CLAIMS = frozenset({"ref", "workflow_ref", "job_workflow_ref"})
_GLOB_CHARS = frozenset("*?[")


@dataclass(frozen=True)
class SecretSpec:
    public_name: str
    source: str
    value: str


@dataclass(frozen=True)
class Bundle:
    name: str
    description: str
    allow: tuple[dict[str, str], ...]
    secrets: tuple[SecretSpec, ...]


@dataclass(frozen=True)
class Policy:
    version: int
    strict: bool
    audit_claims: tuple[str, ...]
    bundles: dict[str, Bundle]

    def require_bundle(self, name: str) -> Bundle:
        try:
            return self.bundles[name]
        except KeyError as exc:
            raise AuthorizationError("credential bundle is not available") from exc


def load_policy(path: Path) -> Policy:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError as exc:
        raise ConfigurationError(f"policy file does not exist: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"policy file is invalid YAML: {path}") from exc

    if raw.get("version") != 1:
        raise ConfigurationError("policy version must be 1")

    strict = raw.get("strict", False)
    if not isinstance(strict, bool):
        raise ConfigurationError("strict must be a boolean")

    defaults = _mapping(raw.get("defaults", {}), "defaults")
    audit_claims_raw = defaults.get("audit_claims", [])
    if not isinstance(audit_claims_raw, list) or not all(
        isinstance(item, str) for item in audit_claims_raw
    ):
        raise ConfigurationError("defaults.audit_claims must be a list of strings")

    bundles_raw = _mapping(raw.get("bundles", {}), "bundles")
    bundles: dict[str, Bundle] = {}
    for bundle_name, bundle_raw_any in bundles_raw.items():
        if not isinstance(bundle_name, str) or not _BUNDLE_NAME_RE.fullmatch(bundle_name):
            raise ConfigurationError(
                "bundle names must be 1-80 characters of letters, numbers, '.', '_', or '-'"
            )
        bundle_raw = _mapping(bundle_raw_any, f"bundles.{bundle_name}")

        allow_raw = bundle_raw.get("allow", [])
        if not isinstance(allow_raw, list) or not allow_raw:
            raise ConfigurationError(f"bundles.{bundle_name}.allow must be non-empty")
        allow: list[dict[str, str]] = []
        for idx, rule_any in enumerate(allow_raw):
            rule = _mapping(rule_any, f"bundles.{bundle_name}.allow[{idx}]")
            if not rule:
                raise ConfigurationError(f"bundles.{bundle_name}.allow[{idx}] is empty")
            normalized_rule: dict[str, str] = {}
            for claim_name, expected in rule.items():
                if not isinstance(claim_name, str) or not isinstance(expected, str):
                    raise ConfigurationError(
                        f"bundles.{bundle_name}.allow[{idx}] entries must be strings"
                    )
                if not _CLAIM_NAME_RE.fullmatch(claim_name):
                    raise ConfigurationError(
                        f"bundles.{bundle_name}.allow[{idx}] claim names must be simple strings"
                    )
                if _has_glob(expected) and claim_name not in _GLOB_ALLOWED_CLAIMS:
                    raise ConfigurationError(
                        f"bundles.{bundle_name}.allow[{idx}].{claim_name} cannot use wildcards"
                    )
                normalized_rule[claim_name] = expected
            if strict and "repository_id" not in normalized_rule:
                raise ConfigurationError(
                    f"bundles.{bundle_name}.allow[{idx}] must include repository_id "
                    "when policy strict mode is enabled"
                )
            allow.append(normalized_rule)

        secrets_raw = _mapping(bundle_raw.get("secrets", {}), f"bundles.{bundle_name}.secrets")
        if not secrets_raw:
            raise ConfigurationError(f"bundles.{bundle_name}.secrets must be non-empty")
        secrets: list[SecretSpec] = []
        for public_name, spec_any in secrets_raw.items():
            if not isinstance(public_name, str) or not _SECRET_NAME_RE.fullmatch(public_name):
                raise ConfigurationError(
                    f"bundles.{bundle_name}.secrets keys must be shell-safe variable names"
                )
            spec = _mapping(spec_any, f"bundles.{bundle_name}.secrets.{public_name}")
            unknown_keys = set(spec) - {"env", "op"}
            if unknown_keys:
                keys = ", ".join(sorted(str(key) for key in unknown_keys))
                raise ConfigurationError(
                    f"bundles.{bundle_name}.secrets.{public_name} has unsupported keys: {keys}"
                )
            source_keys = {"env", "op"} & spec.keys()
            if len(source_keys) != 1:
                raise ConfigurationError(
                    f"bundles.{bundle_name}.secrets.{public_name} must set exactly one "
                    "of env or op"
                )

            if "env" in source_keys:
                env_name = spec.get("env")
                if not isinstance(env_name, str) or not _SECRET_NAME_RE.fullmatch(env_name):
                    raise ConfigurationError(
                        f"bundles.{bundle_name}.secrets.{public_name}.env must be a "
                        "shell-safe variable name"
                    )
                secrets.append(
                    SecretSpec(public_name=public_name, source="env", value=env_name)
                )
                continue

            op_ref = spec.get("op")
            if not isinstance(op_ref, str) or not _valid_onepassword_ref(op_ref):
                raise ConfigurationError(
                    f"bundles.{bundle_name}.secrets.{public_name}.op must be an "
                    "op:// secret reference"
                )
            secrets.append(SecretSpec(public_name=public_name, source="op", value=op_ref))

        bundles[bundle_name] = Bundle(
            name=bundle_name,
            description=str(bundle_raw.get("description") or ""),
            allow=tuple(allow),
            secrets=tuple(secrets),
        )

    return Policy(
        version=1,
        strict=strict,
        audit_claims=tuple(audit_claims_raw),
        bundles=bundles,
    )


def authorize_bundle(bundle: Bundle, claims: dict[str, Any]) -> None:
    for rule in bundle.allow:
        if _rule_matches(rule, claims):
            return
    raise AuthorizationError("identity is not allowed to access credential bundle")


def audit_claims(policy: Policy, claims: dict[str, Any]) -> dict[str, str]:
    return {
        claim_name: str(claims[claim_name])
        for claim_name in policy.audit_claims
        if claim_name in claims and claims[claim_name] is not None
    }


def _rule_matches(rule: dict[str, str], claims: dict[str, Any]) -> bool:
    for claim_name, expected in rule.items():
        actual = claims.get(claim_name)
        if actual is None:
            return False
        if not isinstance(actual, str):
            return False
        if not fnmatchcase(actual, expected):
            return False
    return True


def _has_glob(value: str) -> bool:
    return any(char in value for char in _GLOB_CHARS)


def _valid_onepassword_ref(value: str) -> bool:
    return (
        value.startswith("op://")
        and len(value) > len("op://")
        and len(value) <= 1024
        and all(char.isprintable() for char in value)
    )


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{name} must be a mapping")
    return value
