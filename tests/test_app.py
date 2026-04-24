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


def test_credentials_endpoint_returns_allowed_bundle(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            defaults:
              audit_claims: [repository, ref, run_id]
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
                "run_id": "123",
            }
        )
        response = client.post(
            "/v1/credentials/deploy",
            headers={"Authorization": "Bearer valid-token"},
        )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert response.json() == {
        "bundle": "deploy",
        "audit": {
            "repository": "cesaregarza/SplatTop",
            "ref": "refs/heads/main",
            "run_id": "123",
        },
        "secrets": {"TOKEN": "secret-value"},
    }


def test_credentials_endpoint_denies_wrong_ref(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
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
                "ref": "refs/heads/feature",
            }
        )
        response = client.post(
            "/v1/credentials/deploy",
            headers={"Authorization": "Bearer valid-token"},
        )

    assert response.status_code == 403


def test_docs_are_not_exposed_by_default(tmp_path, monkeypatch):
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
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404
