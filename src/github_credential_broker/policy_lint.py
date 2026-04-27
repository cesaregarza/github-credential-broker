from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from github_credential_broker.policy import Capability, Grant, Policy

_GLOB_CHARS = frozenset("*?[")
_PRODUCTION_TERMS = frozenset(
    {
        "deploy",
        "deployment",
        "digitalocean",
        "docr",
        "k8s",
        "kubernetes",
        "prod",
        "production",
        "release",
    }
)
_HIGH_RISK_TERMS = _PRODUCTION_TERMS | frozenset(
    {
        "admin",
        "cloud",
        "database",
        "db",
        "write",
        "spaces",
        "token",
    }
)


@dataclass(frozen=True)
class PolicyLintWarning:
    message: str


def lint_policy(policy: Policy) -> list[PolicyLintWarning]:
    warnings: list[PolicyLintWarning] = []
    warnings.extend(_lint_grant_rules(policy))
    warnings.extend(_lint_shared_onepassword_items(policy))
    return warnings


def _lint_grant_rules(policy: Policy) -> list[PolicyLintWarning]:
    warnings: list[PolicyLintWarning] = []
    for grant_idx, grant in enumerate(policy.grants):
        production_capabilities = _production_capability_names(policy, grant)
        high_risk_capabilities = _high_risk_capability_names(policy, grant)

        for rule_idx, rule in enumerate(grant.allow):
            context = f"grants[{grant_idx}].allow[{rule_idx}]"
            if "repository_id" not in rule:
                warnings.append(
                    PolicyLintWarning(f"{context} is missing stable repository_id")
                )
            if "repository_owner_id" not in rule:
                warnings.append(
                    PolicyLintWarning(f"{context} is missing stable repository_owner_id")
                )
            if production_capabilities and "environment" not in rule:
                names = ", ".join(production_capabilities)
                warnings.append(
                    PolicyLintWarning(
                        f"{context} grants production-looking capability without "
                        f"environment: {names}"
                    )
                )
            for claim_name in ("ref", "workflow_ref", "job_workflow_ref"):
                value = rule.get(claim_name)
                if value is not None and _has_glob(value):
                    warnings.append(
                        PolicyLintWarning(f"{context}.{claim_name} uses a wildcard")
                    )
            if len(high_risk_capabilities) > 1 and _is_broad_rule(rule):
                names = ", ".join(high_risk_capabilities)
                warnings.append(
                    PolicyLintWarning(
                        f"{context} grants multiple high-risk capabilities with a "
                        f"broad rule: {names}"
                    )
                )
    return warnings


def _lint_shared_onepassword_items(policy: Policy) -> list[PolicyLintWarning]:
    item_capabilities: dict[str, set[str]] = defaultdict(set)
    for capability in policy.capabilities.values():
        for secret in capability.secrets:
            if secret.source != "op":
                continue
            item_path = _onepassword_item_path(secret.value)
            if item_path is not None:
                item_capabilities[item_path].add(capability.name)

    warnings: list[PolicyLintWarning] = []
    for item_path, capability_names in sorted(item_capabilities.items()):
        if len(capability_names) <= 1:
            continue
        names = ", ".join(sorted(capability_names))
        warnings.append(
            PolicyLintWarning(
                f"multiple capabilities share 1Password item {item_path}: {names}"
            )
        )
    return warnings


def _production_capability_names(policy: Policy, grant: Grant) -> tuple[str, ...]:
    return tuple(
        name
        for name in grant.capabilities
        if _is_production_capability(policy.capabilities[name])
    )


def _high_risk_capability_names(policy: Policy, grant: Grant) -> tuple[str, ...]:
    return tuple(
        name
        for name in grant.capabilities
        if _is_high_risk_capability(policy.capabilities[name])
    )


def _is_production_capability(capability: Capability) -> bool:
    return _has_term(capability, _PRODUCTION_TERMS)


def _is_high_risk_capability(capability: Capability) -> bool:
    return _has_term(capability, _HIGH_RISK_TERMS)


def _has_term(capability: Capability, terms: frozenset[str]) -> bool:
    haystack = f"{capability.name} {capability.description}".lower()
    return any(term in haystack for term in terms)


def _is_broad_rule(rule: dict[str, str]) -> bool:
    if "repository_id" not in rule or "repository_owner_id" not in rule:
        return True
    workflow_claims = ("ref", "workflow_ref", "job_workflow_ref")
    if any(_has_glob(rule.get(claim_name, "")) for claim_name in workflow_claims):
        return True
    return len(rule) <= 2


def _has_glob(value: str) -> bool:
    return any(char in value for char in _GLOB_CHARS)


def _onepassword_item_path(secret_ref: str) -> str | None:
    if not secret_ref.startswith("op://"):
        return None
    parts = secret_ref.removeprefix("op://").split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return None
    return f"op://{parts[0]}/{parts[1]}"
