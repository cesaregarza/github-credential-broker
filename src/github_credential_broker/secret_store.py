from __future__ import annotations

import os

from github_credential_broker.errors import ConfigurationError
from github_credential_broker.policy import Bundle


class EnvSecretStore:
    def resolve_bundle(self, bundle: Bundle) -> dict[str, str]:
        resolved: dict[str, str] = {}
        missing: list[str] = []

        for spec in bundle.secrets:
            value = os.environ.get(spec.env_name)
            if value is None:
                missing.append(spec.env_name)
                continue
            resolved[spec.public_name] = value

        if missing:
            missing_names = ", ".join(sorted(missing))
            raise ConfigurationError(f"broker secret environment is missing: {missing_names}")

        return resolved

