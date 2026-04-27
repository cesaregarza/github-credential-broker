from __future__ import annotations

import ipaddress
import json
import logging
from collections.abc import Iterable, Mapping
from typing import Any

from fastapi import Request

from github_credential_broker.settings import Settings

SAFE_DENIAL_CLAIMS = (
    "repository",
    "repository_id",
    "repository_owner",
    "repository_owner_id",
    "ref",
    "environment",
    "workflow_ref",
    "job_workflow_ref",
    "run_id",
    "run_attempt",
    "actor",
    "actor_id",
)


def log_audit_event(logger: logging.Logger, event: str, **fields: Any) -> None:
    payload = {"event": event, **fields}
    logger.info("broker_audit %s", json.dumps(payload, sort_keys=True, separators=(",", ":")))


def safe_requested_capabilities(values: Iterable[str], *, max_items: int = 50) -> list[str]:
    sanitized: list[str] = []
    for value in values:
        if len(sanitized) >= max_items:
            sanitized.append("<truncated>")
            break
        sanitized.append(str(value)[:80])
    return sanitized


def safe_verified_claims(claims: Mapping[str, Any]) -> dict[str, str]:
    return {
        name: str(claims[name])[:256]
        for name in SAFE_DENIAL_CLAIMS
        if claims.get(name) is not None
    }


def client_ip(request: Request, settings: Settings) -> str:
    immediate_peer = request.client.host if request.client else ""
    if _trusted_forwarder(immediate_peer, settings):
        forwarded_for = request.headers.get("x-forwarded-for", "")
        forwarded_ip = _first_valid_forwarded_ip(forwarded_for)
        if forwarded_ip:
            return forwarded_ip
    return immediate_peer


def _trusted_forwarder(peer: str, settings: Settings) -> bool:
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return False
    if peer_ip.is_loopback:
        return True
    for cidr in settings.trusted_proxy_cidrs:
        try:
            if peer_ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _first_valid_forwarded_ip(value: str) -> str | None:
    for part in value.split(","):
        candidate = part.strip()
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return candidate
    return None
