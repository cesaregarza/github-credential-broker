from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from github_credential_broker.errors import ConfigurationError
from github_credential_broker.policy import Capability


@dataclass(frozen=True)
class _CachedSecret:
    value: str
    expires_at: float


class SecretStore:
    def __init__(
        self,
        *,
        onepassword_cli_path: str = "op",
        onepassword_timeout_seconds: int = 10,
        onepassword_cache_seconds: int = 60,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self._op_cli_path = onepassword_cli_path
        self._op_timeout_seconds = onepassword_timeout_seconds
        self._op_cache_seconds = onepassword_cache_seconds
        self._runner = runner
        self._op_cache: dict[str, _CachedSecret] = {}

    def resolve_capabilities(self, capabilities: Sequence[Capability]) -> dict[str, str]:
        resolved: dict[str, str] = {}
        missing: list[str] = []

        for capability in capabilities:
            for spec in capability.secrets:
                if spec.public_name in resolved:
                    raise ConfigurationError(
                        f"duplicate secret response name across requested capabilities: "
                        f"{spec.public_name}"
                    )
                if spec.source == "env":
                    value = os.environ.get(spec.value)
                    if value is None:
                        missing.append(spec.value)
                        continue
                    resolved[spec.public_name] = value
                elif spec.source == "op":
                    resolved[spec.public_name] = self._read_onepassword_ref(spec.value)
                else:
                    raise ConfigurationError(f"unsupported secret source: {spec.source}")

        if missing:
            missing_names = ", ".join(sorted(missing))
            raise ConfigurationError(f"broker secret environment is missing: {missing_names}")

        return resolved

    def _read_onepassword_ref(self, secret_ref: str) -> str:
        now = time.monotonic()
        cached = self._op_cache.get(secret_ref)
        if cached is not None and cached.expires_at > now:
            return cached.value

        result = self._run_onepassword_read([self._op_cli_path, "read", "--no-newline", secret_ref])
        if result.returncode != 0:
            raise ConfigurationError("1Password CLI failed to resolve a broker secret")

        value = result.stdout
        if self._op_cache_seconds > 0:
            self._op_cache[secret_ref] = _CachedSecret(
                value=value,
                expires_at=now + self._op_cache_seconds,
            )
        return value

    def _run_onepassword_read(
        self,
        command: Sequence[str],
    ) -> subprocess.CompletedProcess[str]:
        try:
            return self._runner(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=self._op_timeout_seconds,
            )
        except FileNotFoundError as exc:
            raise ConfigurationError("1Password CLI is not installed or not on PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise ConfigurationError("1Password CLI timed out resolving a broker secret") from exc


EnvSecretStore = SecretStore
