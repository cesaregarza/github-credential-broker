from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from github_credential_broker.errors import AuthorizationError, ConfigurationError

_CAPABILITY_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
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
class Capability:
    name: str
    description: str
    secrets: tuple[SecretSpec, ...]


@dataclass(frozen=True)
class Grant:
    description: str
    allow: tuple[dict[str, str], ...]
    capabilities: tuple[str, ...]


@dataclass(frozen=True)
class Policy:
    version: int
    strict: bool
    audit_claims: tuple[str, ...]
    capabilities: dict[str, Capability]
    grants: tuple[Grant, ...]

    def require_capability(self, name: str) -> Capability:
        try:
            return self.capabilities[name]
        except KeyError as exc:
            raise AuthorizationError("credential capability is not available") from exc


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

    uses_legacy_bundles = "bundles" in raw
    uses_capabilities = "capabilities" in raw or "grants" in raw
    if uses_legacy_bundles and uses_capabilities:
        raise ConfigurationError("policy cannot mix legacy bundles with capabilities/grants")

    if uses_legacy_bundles:
        capabilities, grants = _parse_legacy_bundles(raw, strict)
    else:
        capabilities = _parse_capabilities(raw)
        grants = tuple(_parse_grants(raw, capabilities, strict))

    return Policy(
        version=1,
        strict=strict,
        audit_claims=tuple(audit_claims_raw),
        capabilities=capabilities,
        grants=grants,
    )


def authorize_capabilities(
    policy: Policy,
    requested_names: list[str] | tuple[str, ...],
    claims: dict[str, Any],
) -> tuple[Capability, ...]:
    if not requested_names:
        raise AuthorizationError("no credential capabilities requested")

    requested = tuple(requested_names)
    if len(set(requested)) != len(requested):
        raise AuthorizationError("duplicate credential capabilities requested")

    for name in requested:
        policy.require_capability(name)

    allowed: set[str] = set()
    for grant in policy.grants:
        if _grant_matches(grant, claims):
            allowed.update(grant.capabilities)

    if not set(requested).issubset(allowed):
        raise AuthorizationError("identity is not allowed to access credential capabilities")

    return tuple(policy.capabilities[name] for name in requested)


def audit_claims(policy: Policy, claims: dict[str, Any]) -> dict[str, str]:
    return {
        claim_name: str(claims[claim_name])
        for claim_name in policy.audit_claims
        if claim_name in claims and claims[claim_name] is not None
    }


def _parse_capabilities(raw: dict[str, Any]) -> dict[str, Capability]:
    capabilities_raw = _mapping(raw.get("capabilities", {}), "capabilities")
    if not capabilities_raw:
        raise ConfigurationError("capabilities must be non-empty")

    capabilities: dict[str, Capability] = {}
    for capability_name, capability_raw_any in capabilities_raw.items():
        if not isinstance(capability_name, str) or not _CAPABILITY_NAME_RE.fullmatch(
            capability_name
        ):
            raise ConfigurationError(
                "capability names must be 1-80 characters of letters, numbers, '.', '_', or '-'"
            )

        capability_raw = _mapping(capability_raw_any, f"capabilities.{capability_name}")
        unknown_keys = set(capability_raw) - {"description", "secrets"}
        if unknown_keys:
            keys = ", ".join(sorted(str(key) for key in unknown_keys))
            raise ConfigurationError(f"capabilities.{capability_name} has unsupported keys: {keys}")

        capabilities[capability_name] = Capability(
            name=capability_name,
            description=str(capability_raw.get("description") or ""),
            secrets=_parse_secrets(
                capability_raw.get("secrets", {}),
                f"capabilities.{capability_name}.secrets",
            ),
        )

    return capabilities


def _parse_legacy_bundles(
    raw: dict[str, Any],
    strict: bool,
) -> tuple[dict[str, Capability], tuple[Grant, ...]]:
    bundles_raw = _mapping(raw.get("bundles", {}), "bundles")
    if not bundles_raw:
        raise ConfigurationError("bundles must be non-empty")

    capabilities: dict[str, Capability] = {}
    grants: list[Grant] = []
    for bundle_name, bundle_raw_any in bundles_raw.items():
        if not isinstance(bundle_name, str) or not _CAPABILITY_NAME_RE.fullmatch(bundle_name):
            raise ConfigurationError(
                "bundle names must be 1-80 characters of letters, numbers, '.', '_', or '-'"
            )

        bundle_raw = _mapping(bundle_raw_any, f"bundles.{bundle_name}")
        unknown_keys = set(bundle_raw) - {"description", "allow", "secrets"}
        if unknown_keys:
            keys = ", ".join(sorted(str(key) for key in unknown_keys))
            raise ConfigurationError(f"bundles.{bundle_name} has unsupported keys: {keys}")

        capabilities[bundle_name] = Capability(
            name=bundle_name,
            description=str(bundle_raw.get("description") or ""),
            secrets=_parse_secrets(
                bundle_raw.get("secrets", {}),
                f"bundles.{bundle_name}.secrets",
            ),
        )
        grants.append(
            Grant(
                description=f"Legacy bundle grant for {bundle_name}",
                allow=_parse_allow(
                    bundle_raw.get("allow", []),
                    f"bundles.{bundle_name}.allow",
                    strict,
                ),
                capabilities=(bundle_name,),
            )
        )

    return capabilities, tuple(grants)


def _parse_grants(
    raw: dict[str, Any],
    capabilities: dict[str, Capability],
    strict: bool,
) -> list[Grant]:
    grants_raw = raw.get("grants", [])
    if not isinstance(grants_raw, list) or not grants_raw:
        raise ConfigurationError("grants must be a non-empty list")

    grants: list[Grant] = []
    for idx, grant_any in enumerate(grants_raw):
        grant_raw = _mapping(grant_any, f"grants[{idx}]")
        unknown_keys = set(grant_raw) - {"description", "allow", "capabilities"}
        if unknown_keys:
            keys = ", ".join(sorted(str(key) for key in unknown_keys))
            raise ConfigurationError(f"grants[{idx}] has unsupported keys: {keys}")

        capability_names = _parse_grant_capability_names(
            grant_raw.get("capabilities", []),
            f"grants[{idx}].capabilities",
            capabilities,
        )
        grants.append(
            Grant(
                description=str(grant_raw.get("description") or ""),
                allow=_parse_allow(grant_raw.get("allow", []), f"grants[{idx}].allow", strict),
                capabilities=capability_names,
            )
        )

    return grants


def _parse_grant_capability_names(
    value: Any,
    context: str,
    capabilities: dict[str, Capability],
) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ConfigurationError(f"{context} must be a non-empty list")

    names: list[str] = []
    for idx, name in enumerate(value):
        if not isinstance(name, str) or not _CAPABILITY_NAME_RE.fullmatch(name):
            raise ConfigurationError(f"{context}[{idx}] must be a valid capability name")
        if name not in capabilities:
            raise ConfigurationError(f"{context}[{idx}] references unknown capability: {name}")
        names.append(name)

    if len(set(names)) != len(names):
        raise ConfigurationError(f"{context} must not contain duplicates")

    return tuple(names)


def _parse_allow(value: Any, context: str, strict: bool) -> tuple[dict[str, str], ...]:
    if not isinstance(value, list) or not value:
        raise ConfigurationError(f"{context} must be non-empty")

    allow: list[dict[str, str]] = []
    for idx, rule_any in enumerate(value):
        rule = _mapping(rule_any, f"{context}[{idx}]")
        if not rule:
            raise ConfigurationError(f"{context}[{idx}] is empty")

        normalized_rule: dict[str, str] = {}
        for claim_name, expected in rule.items():
            if not isinstance(claim_name, str) or not isinstance(expected, str):
                raise ConfigurationError(f"{context}[{idx}] entries must be strings")
            if not _CLAIM_NAME_RE.fullmatch(claim_name):
                raise ConfigurationError(f"{context}[{idx}] claim names must be simple strings")
            if _has_glob(expected) and claim_name not in _GLOB_ALLOWED_CLAIMS:
                raise ConfigurationError(f"{context}[{idx}].{claim_name} cannot use wildcards")
            normalized_rule[claim_name] = expected

        if strict and "repository_id" not in normalized_rule:
            raise ConfigurationError(
                f"{context}[{idx}] must include repository_id when policy strict mode is enabled"
            )
        allow.append(normalized_rule)

    return tuple(allow)


def _parse_secrets(value: Any, context: str) -> tuple[SecretSpec, ...]:
    secrets_raw = _mapping(value, context)
    if not secrets_raw:
        raise ConfigurationError(f"{context} must be non-empty")

    secrets: list[SecretSpec] = []
    for public_name, spec_any in secrets_raw.items():
        if not isinstance(public_name, str) or not _SECRET_NAME_RE.fullmatch(public_name):
            raise ConfigurationError(f"{context} keys must be shell-safe variable names")

        spec = _mapping(spec_any, f"{context}.{public_name}")
        unknown_keys = set(spec) - {"env", "op"}
        if unknown_keys:
            keys = ", ".join(sorted(str(key) for key in unknown_keys))
            raise ConfigurationError(f"{context}.{public_name} has unsupported keys: {keys}")

        source_keys = {"env", "op"} & spec.keys()
        if len(source_keys) != 1:
            raise ConfigurationError(f"{context}.{public_name} must set exactly one of env or op")

        if "env" in source_keys:
            env_name = spec.get("env")
            if not isinstance(env_name, str) or not _SECRET_NAME_RE.fullmatch(env_name):
                raise ConfigurationError(
                    f"{context}.{public_name}.env must be a shell-safe variable name"
                )
            secrets.append(SecretSpec(public_name=public_name, source="env", value=env_name))
            continue

        op_ref = spec.get("op")
        if not isinstance(op_ref, str) or not _valid_onepassword_ref(op_ref):
            raise ConfigurationError(
                f"{context}.{public_name}.op must be an op:// secret reference"
            )
        secrets.append(SecretSpec(public_name=public_name, source="op", value=op_ref))

    return tuple(secrets)


def _grant_matches(grant: Grant, claims: dict[str, Any]) -> bool:
    return any(_rule_matches(rule, claims) for rule in grant.allow)


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
