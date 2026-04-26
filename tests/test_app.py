from __future__ import annotations

import textwrap

from fastapi.testclient import TestClient

from github_credential_broker.app import create_app


class FakeVerifier:
    def __init__(self, claims):
        self._claims = claims

    def verify(self, token: str):
        assert token == "valid-token"
        return self._claims


def test_capabilities_endpoint_returns_allowed_credentials(tmp_path, monkeypatch):
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


def test_capabilities_endpoint_denies_wrong_ref(tmp_path, monkeypatch):
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

    app = create_app()
    with TestClient(app) as client:
        client.app.state.broker.verifier = FakeVerifier(
            {
                "repository": "cesaregarza/SplatTop",
                "ref": "refs/heads/feature",
            }
        )
        response = client.post(
            "/v1/capabilities",
            headers={"Authorization": "Bearer valid-token"},
            json={"capabilities": ["deploy"]},
        )

    assert response.status_code == 403


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
