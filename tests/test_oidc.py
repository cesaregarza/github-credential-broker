from __future__ import annotations

import pytest

from github_credential_broker.errors import AuthenticationError
from github_credential_broker.oidc import extract_bearer_token


def test_extract_bearer_token():
    assert extract_bearer_token("Bearer abc.def") == "abc.def"


def test_extract_bearer_token_rejects_oversized_token():
    with pytest.raises(AuthenticationError):
        extract_bearer_token("Bearer " + ("a" * 9), max_length=8)


@pytest.mark.parametrize("header", [None, "", "Basic abc", "Bearer "])
def test_extract_bearer_token_rejects_invalid_header(header):
    with pytest.raises(AuthenticationError):
        extract_bearer_token(header)
