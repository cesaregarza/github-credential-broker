from __future__ import annotations

import pytest
from jwt import PyJWKClientConnectionError, PyJWKClientError

from github_credential_broker.errors import AuthenticationError, ConfigurationError
from github_credential_broker.oidc import GitHubOIDCVerifier, extract_bearer_token
from github_credential_broker.settings import Settings


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
