from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _broker_oidc_audience(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BROKER_GITHUB_OIDC_AUDIENCE", "https://broker.test/v1")
