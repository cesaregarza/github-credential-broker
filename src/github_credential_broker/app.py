from __future__ import annotations

import logging
import re
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Path, Request, Response, status
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
    app.state.broker = BrokerState(app.state.settings)
    yield


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    docs_url = "/docs" if settings.expose_docs else None
    redoc_url = "/redoc" if settings.expose_docs else None
    openapi_url = "/openapi.json" if settings.expose_docs else None

    app = FastAPI(
        title="GitHub Credential Broker",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
    )
    app.state.settings = settings

    @app.get("/healthz", response_model=HealthResponse)
    async def healthz() -> HealthResponse:
        return HealthResponse(ok=True)

    bundle_path = Path(
        min_length=1,
        max_length=settings.max_bundle_name_length,
        pattern=_BUNDLE_RE.pattern,
    )

    @app.post("/v1/credentials/{bundle_name}", response_model=CredentialsResponse)
    async def credentials(
        request: Request,
        response: Response,
        bundle_name: str = bundle_path,
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    ) -> CredentialsResponse:
        broker: BrokerState = request.app.state.broker
        try:
            token = extract_bearer_token(
                authorization,
                max_length=broker.settings.max_bearer_token_length,
            )
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
        response.headers["Cache-Control"] = "no-store"
        return CredentialsResponse(bundle=bundle_name, audit=audit, secrets=secrets)

    return app
