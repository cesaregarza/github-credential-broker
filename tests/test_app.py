from __future__ import annotations

import logging
import textwrap

from fastapi.testclient import TestClient

from github_credential_broker.app import create_app
from github_credential_broker.errors import AuthenticationError


class FakeVerifier:
    def __init__(self, claims, *, expected_token: str | None = "valid-token"):
        self._claims = claims
        self._expected_token = expected_token

    def verify(self, token: str):
        if self._expected_token is not None:
            assert token == self._expected_token
        return self._claims


class MappingVerifier:
    def __init__(self, claims_by_token):
        self._claims_by_token = claims_by_token

    def verify(self, token: str):
        return self._claims_by_token[token]


class RaisingVerifier:
    def __init__(self, exc):
        self._exc = exc

    def verify(self, token: str):
        raise self._exc


def test_capabilities_endpoint_returns_allowed_credentials(tmp_path, monkeypatch, caplog):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            defaults:
              audit_claims: [repository, ref, run_id]
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: REAL_TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                    ref: refs/heads/main
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("BROKER_POLICY_PATH", str(policy_path))
    monkeypatch.setenv("REAL_TOKEN", "secret-value")
    caplog.set_level(logging.INFO, logger="github_credential_broker.app")

    app = create_app()
    with TestClient(app) as client:
        client.app.state.broker.verifier = FakeVerifier(
            {
                "repository": "cesaregarza/SplatTop",
                "ref": "refs/heads/main",
                "run_id": "123",
            }
        )
        response = client.post(
            "/v1/capabilities",
            headers={"Authorization": "Bearer valid-token"},
            json={"capabilities": ["deploy"]},
        )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "pragma" not in response.headers
    assert response.json() == {
        "capabilities": ["deploy"],
        "audit": {
            "repository": "cesaregarza/SplatTop",
            "ref": "refs/heads/main",
            "run_id": "123",
        },
        "secrets": {"TOKEN": "secret-value"},
    }
    assert "credential_issued" in caplog.text
    assert "secret-value" not in caplog.text


def test_capabilities_endpoint_denies_wrong_ref(tmp_path, monkeypatch, caplog):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: REAL_TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                    ref: refs/heads/main
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("BROKER_POLICY_PATH", str(policy_path))
    monkeypatch.setenv("REAL_TOKEN", "secret-value")
    caplog.set_level(logging.INFO, logger="github_credential_broker.app")

    app = create_app()
    with TestClient(app) as client:
        client.app.state.broker.verifier = FakeVerifier(
            {
                "repository": "cesaregarza/SplatTop",
                "repository_id": "679054126",
                "ref": "refs/heads/feature",
            }
        )
        response = client.post(
            "/v1/capabilities",
            headers={"Authorization": "Bearer valid-token"},
            json={"capabilities": ["deploy"]},
        )

    assert response.status_code == 403
    assert "authorization_denied" in caplog.text
    assert "repository_id" in caplog.text
    assert "679054126" in caplog.text
    assert "secret-value" not in caplog.text


def test_capabilities_endpoint_logs_authentication_failure(tmp_path, monkeypatch, caplog):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: REAL_TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("BROKER_POLICY_PATH", str(policy_path))
    monkeypatch.setenv("REAL_TOKEN", "secret-value")
    caplog.set_level(logging.INFO, logger="github_credential_broker.app")

    app = create_app()
    with TestClient(app) as client:
        response = client.post("/v1/capabilities", json={"capabilities": ["deploy"]})

    assert response.status_code == 401
    assert "authentication_denied" in caplog.text
    assert "missing_bearer" in caplog.text
    assert "secret-value" not in caplog.text
    assert "Bearer" not in caplog.text


def test_capabilities_endpoint_logs_replay_failure(tmp_path, monkeypatch, caplog):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: REAL_TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("BROKER_POLICY_PATH", str(policy_path))
    monkeypatch.setenv("REAL_TOKEN", "secret-value")
    caplog.set_level(logging.INFO, logger="github_credential_broker.app")

    app = create_app()
    with TestClient(app) as client:
        client.app.state.broker.verifier = RaisingVerifier(
            AuthenticationError("replayed", reason="replayed_jti")
        )
        response = client.post(
            "/v1/capabilities",
            headers={"Authorization": "Bearer token-material"},
            json={"capabilities": ["deploy"]},
        )

    assert response.status_code == 401
    assert "authentication_denied" in caplog.text
    assert "replayed_jti" in caplog.text
    assert "token-material" not in caplog.text
    assert "secret-value" not in caplog.text


def test_legacy_credentials_endpoint_supports_legacy_bundle_policy(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            defaults:
              audit_claims: [repository, ref]
            bundles:
              deploy:
                allow:
                  - repository: cesaregarza/SplatTop
                    ref: refs/heads/main
                secrets:
                  TOKEN:
                    env: REAL_TOKEN
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("BROKER_POLICY_PATH", str(policy_path))
    monkeypatch.setenv("BROKER_ENABLE_LEGACY_CREDENTIALS", "true")
    monkeypatch.setenv("REAL_TOKEN", "secret-value")

    app = create_app()
    with TestClient(app) as client:
        client.app.state.broker.verifier = FakeVerifier(
            {
                "repository": "cesaregarza/SplatTop",
                "ref": "refs/heads/main",
            }
        )
        response = client.post(
            "/v1/credentials/deploy",
            headers={"Authorization": "Bearer valid-token"},
        )

    assert response.status_code == 200
    assert response.json() == {
        "bundle": "deploy",
        "audit": {
            "repository": "cesaregarza/SplatTop",
            "ref": "refs/heads/main",
        },
        "secrets": {"TOKEN": "secret-value"},
    }


def test_legacy_credentials_endpoint_is_disabled_by_default(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            bundles:
              deploy:
                allow:
                  - repository: cesaregarza/SplatTop
                secrets:
                  TOKEN:
                    env: REAL_TOKEN
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("BROKER_POLICY_PATH", str(policy_path))
    monkeypatch.setenv("REAL_TOKEN", "secret-value")

    app = create_app()
    with TestClient(app) as client:
        response = client.post(
            "/v1/credentials/deploy",
            headers={"Authorization": "Bearer valid-token"},
        )

    assert response.status_code == 404


def test_capabilities_endpoint_denies_unrequested_or_unknown_capability(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: REAL_TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("BROKER_POLICY_PATH", str(policy_path))
    monkeypatch.setenv("REAL_TOKEN", "secret-value")

    app = create_app()
    with TestClient(app) as client:
        client.app.state.broker.verifier = FakeVerifier(
            {
                "repository": "cesaregarza/SplatTop",
                "ref": "refs/heads/main",
            }
        )
        response = client.post(
            "/v1/capabilities",
            headers={"Authorization": "Bearer valid-token"},
            json={"capabilities": ["missing"]},
        )

    assert response.status_code == 403


def test_capabilities_endpoint_rejects_duplicate_requested_capability(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: REAL_TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("BROKER_POLICY_PATH", str(policy_path))
    monkeypatch.setenv("REAL_TOKEN", "secret-value")

    app = create_app()
    with TestClient(app) as client:
        response = client.post(
            "/v1/capabilities",
            headers={"Authorization": "Bearer valid-token"},
            json={"capabilities": ["deploy", "deploy"]},
        )

    assert response.status_code == 422


def test_ip_rate_limit_returns_429_after_limit(tmp_path, monkeypatch):
    _install_simple_policy(tmp_path, monkeypatch)
    monkeypatch.setenv("BROKER_RATE_LIMIT_IP_PER_MINUTE", "2")
    monkeypatch.setenv("BROKER_RATE_LIMIT_IDENTITY_PER_MINUTE", "100")

    app = create_app()
    with TestClient(app, client=("203.0.113.10", 50000)) as client:
        client.app.state.broker.verifier = FakeVerifier(
            {"repository": "cesaregarza/SplatTop"},
            expected_token=None,
        )
        responses = [
            client.post(
                "/v1/capabilities",
                headers={"Authorization": "Bearer valid-token"},
                json={"capabilities": ["deploy"]},
            )
            for _ in range(3)
        ]

    assert [response.status_code for response in responses] == [200, 200, 429]


def test_untrusted_x_forwarded_for_is_ignored_for_rate_limit(tmp_path, monkeypatch):
    _install_simple_policy(tmp_path, monkeypatch)
    monkeypatch.setenv("BROKER_RATE_LIMIT_IP_PER_MINUTE", "1")
    monkeypatch.setenv("BROKER_RATE_LIMIT_IDENTITY_PER_MINUTE", "100")

    app = create_app()
    with TestClient(app, client=("203.0.113.10", 50000)) as client:
        client.app.state.broker.verifier = FakeVerifier(
            {"repository": "cesaregarza/SplatTop"},
            expected_token=None,
        )
        first = client.post(
            "/v1/capabilities",
            headers={
                "Authorization": "Bearer valid-token",
                "X-Forwarded-For": "198.51.100.1",
            },
            json={"capabilities": ["deploy"]},
        )
        second = client.post(
            "/v1/capabilities",
            headers={
                "Authorization": "Bearer valid-token",
                "X-Forwarded-For": "198.51.100.2",
            },
            json={"capabilities": ["deploy"]},
        )

    assert first.status_code == 200
    assert second.status_code == 429


def test_trusted_x_forwarded_for_is_used_for_rate_limit(tmp_path, monkeypatch):
    _install_simple_policy(tmp_path, monkeypatch)
    monkeypatch.setenv("BROKER_RATE_LIMIT_IP_PER_MINUTE", "1")
    monkeypatch.setenv("BROKER_RATE_LIMIT_IDENTITY_PER_MINUTE", "100")

    app = create_app()
    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        client.app.state.broker.verifier = FakeVerifier(
            {"repository": "cesaregarza/SplatTop"},
            expected_token=None,
        )
        first = client.post(
            "/v1/capabilities",
            headers={
                "Authorization": "Bearer valid-token",
                "X-Forwarded-For": "198.51.100.1",
            },
            json={"capabilities": ["deploy"]},
        )
        second = client.post(
            "/v1/capabilities",
            headers={
                "Authorization": "Bearer valid-token",
                "X-Forwarded-For": "198.51.100.2",
            },
            json={"capabilities": ["deploy"]},
        )

    assert first.status_code == 200
    assert second.status_code == 200


def test_identity_rate_limit_uses_repository_id(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: REAL_TOKEN
            grants:
              - allow:
                  - repository_id: "123"
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("BROKER_POLICY_PATH", str(policy_path))
    monkeypatch.setenv("REAL_TOKEN", "secret-value")
    monkeypatch.setenv("BROKER_RATE_LIMIT_IP_PER_MINUTE", "100")
    monkeypatch.setenv("BROKER_RATE_LIMIT_IDENTITY_PER_MINUTE", "1")

    app = create_app()
    with TestClient(app) as client:
        client.app.state.broker.verifier = MappingVerifier(
            {
                "token-a": {"repository": "owner/repo-a", "repository_id": "123"},
                "token-b": {"repository": "owner/repo-b", "repository_id": "123"},
            }
        )
        first = client.post(
            "/v1/capabilities",
            headers={"Authorization": "Bearer token-a"},
            json={"capabilities": ["deploy"]},
        )
        second = client.post(
            "/v1/capabilities",
            headers={"Authorization": "Bearer token-b"},
            json={"capabilities": ["deploy"]},
        )

    assert first.status_code == 200
    assert second.status_code == 429


def test_healthz_returns_ok(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: REAL_TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("BROKER_POLICY_PATH", str(policy_path))
    monkeypatch.setenv("REAL_TOKEN", "secret-value")

    app = create_app()
    with TestClient(app) as client:
        response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_docs_are_not_exposed_by_default(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: REAL_TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("BROKER_POLICY_PATH", str(policy_path))
    monkeypatch.setenv("REAL_TOKEN", "secret-value")

    app = create_app()
    with TestClient(app) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404


def _install_simple_policy(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            capabilities:
              deploy:
                secrets:
                  TOKEN:
                    env: REAL_TOKEN
            grants:
              - allow:
                  - repository: cesaregarza/SplatTop
                capabilities: [deploy]
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("BROKER_POLICY_PATH", str(policy_path))
    monkeypatch.setenv("REAL_TOKEN", "secret-value")
