from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from github_credential_broker.errors import AuthorizationError, ConfigurationError


@dataclass(frozen=True)
class SecretSpec:
    public_name: str
    env_name: str


@dataclass(frozen=True)
class Bundle:
    name: str
    description: str
    allow: tuple[dict[str, str], ...]
    secrets: tuple[SecretSpec, ...]


@dataclass(frozen=True)
class Policy:
    version: int
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

    defaults = _mapping(raw.get("defaults", {}), "defaults")
    audit_claims_raw = defaults.get("audit_claims", [])
    if not isinstance(audit_claims_raw, list) or not all(
        isinstance(item, str) for item in audit_claims_raw
    ):
        raise ConfigurationError("defaults.audit_claims must be a list of strings")

    bundles_raw = _mapping(raw.get("bundles", {}), "bundles")
    bundles: dict[str, Bundle] = {}
    for bundle_name, bundle_raw_any in bundles_raw.items():
        if not isinstance(bundle_name, str) or not bundle_name:
            raise ConfigurationError("bundle names must be non-empty strings")
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
                normalized_rule[claim_name] = expected
            allow.append(normalized_rule)

        secrets_raw = _mapping(bundle_raw.get("secrets", {}), f"bundles.{bundle_name}.secrets")
        if not secrets_raw:
            raise ConfigurationError(f"bundles.{bundle_name}.secrets must be non-empty")
        secrets: list[SecretSpec] = []
        for public_name, spec_any in secrets_raw.items():
            if not isinstance(public_name, str) or not public_name:
                raise ConfigurationError(
                    f"bundles.{bundle_name}.secrets keys must be non-empty strings"
                )
            spec = _mapping(spec_any, f"bundles.{bundle_name}.secrets.{public_name}")
            env_name = spec.get("env")
            if not isinstance(env_name, str) or not env_name:
                raise ConfigurationError(
                    f"bundles.{bundle_name}.secrets.{public_name}.env is required"
                )
            secrets.append(SecretSpec(public_name=public_name, env_name=env_name))

        bundles[bundle_name] = Bundle(
            name=bundle_name,
            description=str(bundle_raw.get("description") or ""),
            allow=tuple(allow),
            secrets=tuple(secrets),
        )

    return Policy(version=1, audit_claims=tuple(audit_claims_raw), bundles=bundles)


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
        if not fnmatchcase(str(actual), expected):
            return False
    return True


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{name} must be a mapping")
    return value

