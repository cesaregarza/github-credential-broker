from __future__ import annotations

import hashlib
import threading
import time
from typing import Any

import jwt
from jwt import PyJWKClient, PyJWKClientConnectionError, PyJWKClientError

from github_credential_broker.errors import AuthenticationError, ConfigurationError
from github_credential_broker.settings import Settings

DEFAULT_MAX_BEARER_TOKEN_LENGTH = 16384


class JWTReplayCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._consumed: dict[str, int] = {}

    def consume(
        self,
        *,
        issuer: str,
        audience: str,
        jti: str,
        expires_at: int,
        now: int | None = None,
    ) -> bool:
        current_time = int(time.time()) if now is None else now
        key = _jti_cache_key(issuer=issuer, audience=audience, jti=jti)
        with self._lock:
            self._purge_expired_locked(now=current_time)
            if key in self._consumed:
                return False
            if expires_at <= current_time:
                return False
            self._consumed[key] = expires_at
            return True

    def purge_expired(self, *, now: int | None = None) -> None:
        current_time = int(time.time()) if now is None else now
        with self._lock:
            self._purge_expired_locked(now=current_time)

    def _purge_expired_locked(self, *, now: int) -> None:
        expired = [key for key, expires_at in self._consumed.items() if expires_at <= now]
        for key in expired:
            del self._consumed[key]


def _jti_cache_key(*, issuer: str, audience: str, jti: str) -> str:
    material = f"{issuer}\0{audience}\0{jti}".encode()
    return hashlib.sha256(material).hexdigest()


class GitHubOIDCVerifier:
    def __init__(self, settings: Settings, replay_cache: JWTReplayCache | None = None) -> None:
        self._settings = settings
        self._replay_cache = replay_cache or JWTReplayCache()
        self._jwks = PyJWKClient(
            settings.github_oidc_jwks_url,
            cache_keys=True,
            lifespan=settings.jwks_cache_seconds,
        )

    def verify(self, token: str) -> dict[str, Any]:
        required_claims = ["aud", "exp", "iat", "iss", "nbf", "sub"]
        if self._settings.require_jti:
            required_claims.append("jti")

        try:
            signing_key = self._jwks.get_signing_key_from_jwt(token)
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._settings.github_oidc_audience,
                issuer=self._settings.github_oidc_issuer,
                options={"require": required_claims},
            )
        except PyJWKClientConnectionError as exc:
            raise ConfigurationError(
                "unable to fetch GitHub OIDC signing keys",
                reason="jwks_error",
            ) from exc
        except PyJWKClientError as exc:
            raise AuthenticationError("invalid GitHub OIDC token", reason="invalid_jwt") from exc
        except jwt.MissingRequiredClaimError as exc:
            reason = "missing_jti" if exc.claim == "jti" else "invalid_jwt"
            raise AuthenticationError("invalid GitHub OIDC token", reason=reason) from exc
        except jwt.PyJWTError as exc:
            raise AuthenticationError("invalid GitHub OIDC token", reason="invalid_jwt") from exc

        if not isinstance(payload, dict):
            raise AuthenticationError("invalid GitHub OIDC token payload", reason="invalid_jwt")

        jti = payload.get("jti")
        if jti is None:
            return payload
        if not isinstance(jti, str) or not jti:
            raise AuthenticationError("invalid GitHub OIDC token identifier", reason="invalid_jti")

        issuer = payload.get("iss")
        expires_at = payload.get("exp")
        if not isinstance(issuer, str) or not isinstance(expires_at, int):
            raise AuthenticationError("invalid GitHub OIDC token payload", reason="invalid_jwt")

        consumed = self._replay_cache.consume(
            issuer=issuer,
            audience=self._settings.github_oidc_audience,
            jti=jti,
            expires_at=expires_at,
        )
        if not consumed:
            raise AuthenticationError(
                "GitHub OIDC token has already been used",
                reason="replayed_jti",
            )
        return payload


def extract_bearer_token(
    authorization_header: str | None,
    *,
    max_length: int = DEFAULT_MAX_BEARER_TOKEN_LENGTH,
) -> str:
    if not authorization_header:
        raise AuthenticationError("missing bearer token", reason="missing_bearer")
    if len(authorization_header) > max_length + len("Bearer "):
        raise AuthenticationError("bearer token is too large", reason="bearer_too_large")

    scheme, _, value = authorization_header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        raise AuthenticationError("missing bearer token", reason="missing_bearer")
    token = value.strip()
    if len(token) > max_length:
        raise AuthenticationError("bearer token is too large", reason="bearer_too_large")
    return token
