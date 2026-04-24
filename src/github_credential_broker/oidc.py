from __future__ import annotations

from typing import Any

import jwt
from jwt import PyJWKClient, PyJWKClientConnectionError, PyJWKClientError

from github_credential_broker.errors import AuthenticationError, ConfigurationError
from github_credential_broker.settings import Settings

DEFAULT_MAX_BEARER_TOKEN_LENGTH = 16384


class GitHubOIDCVerifier:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._jwks = PyJWKClient(
            settings.github_oidc_jwks_url,
            cache_keys=True,
            lifespan=settings.jwks_cache_seconds,
        )

    def verify(self, token: str) -> dict[str, Any]:
        try:
            signing_key = self._jwks.get_signing_key_from_jwt(token)
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._settings.github_oidc_audience,
                issuer=self._settings.github_oidc_issuer,
                options={"require": ["aud", "exp", "iat", "iss", "nbf", "sub"]},
            )
        except PyJWKClientConnectionError as exc:
            raise ConfigurationError("unable to fetch GitHub OIDC signing keys") from exc
        except PyJWKClientError as exc:
            raise AuthenticationError("invalid GitHub OIDC token") from exc
        except jwt.PyJWTError as exc:
            raise AuthenticationError("invalid GitHub OIDC token") from exc

        if not isinstance(payload, dict):
            raise AuthenticationError("invalid GitHub OIDC token payload")
        return payload


def extract_bearer_token(
    authorization_header: str | None,
    *,
    max_length: int = DEFAULT_MAX_BEARER_TOKEN_LENGTH,
) -> str:
    if not authorization_header:
        raise AuthenticationError("missing bearer token")
    if len(authorization_header) > max_length + len("Bearer "):
        raise AuthenticationError("bearer token is too large")

    scheme, _, value = authorization_header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        raise AuthenticationError("missing bearer token")
    token = value.strip()
    if len(token) > max_length:
        raise AuthenticationError("bearer token is too large")
    return token
