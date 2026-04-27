from __future__ import annotations

import time

import jwt
import pytest
from jwt import PyJWKClientConnectionError, PyJWKClientError

from github_credential_broker.errors import AuthenticationError, ConfigurationError
from github_credential_broker.oidc import GitHubOIDCVerifier, JWTReplayCache, extract_bearer_token
from github_credential_broker.settings import Settings


class FakeSigningKey:
    key = "fake-key"


def test_extract_bearer_token():
    assert extract_bearer_token("Bearer abc.def") == "abc.def"


def test_extract_bearer_token_rejects_oversized_token():
    with pytest.raises(AuthenticationError):
        extract_bearer_token("Bearer " + ("a" * 9), max_length=8)


@pytest.mark.parametrize("header", [None, "", "Basic abc", "Bearer "])
def test_extract_bearer_token_rejects_invalid_header(header):
    with pytest.raises(AuthenticationError):
        extract_bearer_token(header)


def test_verifier_rejects_malformed_token():
    verifier = GitHubOIDCVerifier(Settings())
    with pytest.raises(AuthenticationError):
        verifier.verify("not-a-jwt")


def test_verifier_treats_unknown_signing_key_as_authentication_error(monkeypatch):
    verifier = GitHubOIDCVerifier(Settings())

    def raise_unknown_key(token: str):
        raise PyJWKClientError("Unable to find a signing key that matches")

    monkeypatch.setattr(verifier._jwks, "get_signing_key_from_jwt", raise_unknown_key)

    with pytest.raises(AuthenticationError):
        verifier.verify("header.payload.signature")


def test_verifier_treats_jwks_connection_error_as_configuration_error(monkeypatch):
    verifier = GitHubOIDCVerifier(Settings())

    def raise_connection_error(token: str):
        raise PyJWKClientConnectionError("connection failed")

    monkeypatch.setattr(verifier._jwks, "get_signing_key_from_jwt", raise_connection_error)

    with pytest.raises(ConfigurationError):
        verifier.verify("header.payload.signature")


def test_verifier_accepts_new_jti_once(monkeypatch):
    verifier = _verifier_with_claims(
        monkeypatch,
        {
            "aud": "test-audience",
            "exp": int(time.time()) + 60,
            "iat": int(time.time()),
            "iss": "https://token.actions.githubusercontent.com",
            "nbf": int(time.time()),
            "sub": "repo:owner/repo",
            "jti": "unique-token-id",
        },
    )

    assert verifier.verify("header.payload.signature")["jti"] == "unique-token-id"
    with pytest.raises(AuthenticationError) as exc_info:
        verifier.verify("header.payload.signature")
    assert exc_info.value.reason == "replayed_jti"


def test_verifier_rejects_missing_jti_by_default(monkeypatch):
    verifier = _verifier_with_claims(
        monkeypatch,
        {
            "aud": "test-audience",
            "exp": int(time.time()) + 60,
            "iat": int(time.time()),
            "iss": "https://token.actions.githubusercontent.com",
            "nbf": int(time.time()),
            "sub": "repo:owner/repo",
        },
    )

    with pytest.raises(AuthenticationError) as exc_info:
        verifier.verify("header.payload.signature")
    assert exc_info.value.reason == "missing_jti"


def test_verifier_accepts_missing_jti_when_disabled(monkeypatch):
    verifier = _verifier_with_claims(
        monkeypatch,
        {
            "aud": "test-audience",
            "exp": int(time.time()) + 60,
            "iat": int(time.time()),
            "iss": "https://token.actions.githubusercontent.com",
            "nbf": int(time.time()),
            "sub": "repo:owner/repo",
        },
        settings=Settings(github_oidc_audience="test-audience", require_jti=False),
    )

    assert verifier.verify("header.payload.signature")["sub"] == "repo:owner/repo"


def test_replay_cache_purges_expired_entries():
    cache = JWTReplayCache()

    assert cache.consume(issuer="iss", audience="aud", jti="jti", expires_at=101, now=100)
    assert not cache.consume(issuer="iss", audience="aud", jti="jti", expires_at=101, now=100)

    cache.purge_expired(now=102)

    assert cache.consume(issuer="iss", audience="aud", jti="jti", expires_at=200, now=102)


def _verifier_with_claims(monkeypatch, claims, settings=None):
    settings = settings or Settings(github_oidc_audience="test-audience")
    verifier = GitHubOIDCVerifier(settings)

    monkeypatch.setattr(
        verifier._jwks,
        "get_signing_key_from_jwt",
        lambda token: FakeSigningKey(),
    )

    def decode(*args, **kwargs):
        required = set(kwargs["options"]["require"])
        for claim_name in required:
            if claim_name not in claims:
                raise jwt.MissingRequiredClaimError(claim_name)
        return claims

    monkeypatch.setattr("github_credential_broker.oidc.jwt.decode", decode)
    return verifier
