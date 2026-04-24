from __future__ import annotations

import logging
import re
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Path, Request, status
from pydantic import BaseModel, Field

from github_credential_broker.errors import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
)
from github_credential_broker.oidc import GitHubOIDCVerifier, extract_bearer_token
from github_credential_broker.policy import audit_claims, authorize_bundle, load_policy
from github_credential_broker.secret_store import EnvSecretStore
from github_credential_broker.settings import Settings, load_settings

logger = logging.getLogger(__name__)
_BUNDLE_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class CredentialsResponse(BaseModel):
    bundle: str
    audit: dict[str, str] = Field(default_factory=dict)
    secrets: dict[str, str] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    ok: bool


class BrokerState:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.policy = load_policy(settings.policy_path)
        self.verifier = GitHubOIDCVerifier(settings)
        self.secret_store = EnvSecretStore()


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.broker = BrokerState(load_settings())
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="GitHub Credential Broker",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.get("/healthz", response_model=HealthResponse)
    async def healthz() -> HealthResponse:
        return HealthResponse(ok=True)

    @app.post("/v1/credentials/{bundle_name}", response_model=CredentialsResponse)
    async def credentials(
        request: Request,
        bundle_name: Annotated[
            str,
            Path(min_length=1, max_length=80, pattern=_BUNDLE_RE.pattern),
        ],
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    ) -> CredentialsResponse:
        broker: BrokerState = request.app.state.broker
        try:
            token = extract_bearer_token(authorization)
            claims = broker.verifier.verify(token)
            bundle = broker.policy.require_bundle(bundle_name)
            authorize_bundle(bundle, claims)
            secrets = broker.secret_store.resolve_bundle(bundle)
        except AuthenticationError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid credentials",
            ) from exc
        except AuthorizationError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="credential bundle is not available",
            ) from exc
        except ConfigurationError:
            logger.exception("Broker configuration error while resolving bundle %s", bundle_name)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="credential bundle is temporarily unavailable",
            ) from None

        audit = audit_claims(broker.policy, claims)
        logger.info(
            "Issued credential bundle",
            extra={"bundle": bundle_name, "audit": audit},
        )
        return CredentialsResponse(bundle=bundle_name, audit=audit, secrets=secrets)

    return app


app = create_app()
