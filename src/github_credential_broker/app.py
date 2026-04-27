from __future__ import annotations

import logging
import re
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Path, Request, Response, status
from pydantic import BaseModel, Field, field_validator

from github_credential_broker.audit import (
    client_ip,
    log_audit_event,
    safe_requested_capabilities,
    safe_verified_claims,
)
from github_credential_broker.errors import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
)
from github_credential_broker.oidc import GitHubOIDCVerifier, extract_bearer_token
from github_credential_broker.policy import (
    audit_claims,
    authorize_capabilities,
    load_policy,
)
from github_credential_broker.rate_limit import SlidingWindowRateLimiter
from github_credential_broker.secret_store import SecretStore
from github_credential_broker.settings import Settings, load_settings

logger = logging.getLogger(__name__)
_CAPABILITY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")


class CredentialsRequest(BaseModel):
    capabilities: list[str] = Field(min_length=1, max_length=50)

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, capabilities: list[str]) -> list[str]:
        seen: set[str] = set()
        for capability in capabilities:
            if not _CAPABILITY_RE.fullmatch(capability):
                raise ValueError(
                    "capabilities must contain only letters, numbers, '.', '_', or '-'"
                )
            if capability in seen:
                raise ValueError("capabilities must not contain duplicates")
            seen.add(capability)
        return capabilities


class CredentialsResponse(BaseModel):
    capabilities: list[str]
    audit: dict[str, str] = Field(default_factory=dict)
    secrets: dict[str, str] = Field(default_factory=dict)


class LegacyCredentialsResponse(BaseModel):
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
        self.secret_store = SecretStore(
            onepassword_cli_path=settings.onepassword_cli_path,
            onepassword_timeout_seconds=settings.onepassword_read_timeout_seconds,
            onepassword_cache_seconds=settings.onepassword_cache_seconds,
        )
        self.ip_rate_limiter = SlidingWindowRateLimiter()
        self.identity_rate_limiter = SlidingWindowRateLimiter()


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

    legacy_name_path = Path(min_length=1, max_length=80, pattern=_CAPABILITY_RE.pattern)

    @app.post("/v1/capabilities", response_model=CredentialsResponse)
    async def credentials(
        credentials_request: CredentialsRequest,
        request: Request,
        response: Response,
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    ) -> CredentialsResponse:
        broker: BrokerState = request.app.state.broker
        requested = credentials_request.capabilities
        claims = None
        try:
            _enforce_ip_rate_limit(broker, request, requested)
            token = extract_bearer_token(
                authorization,
                max_length=broker.settings.max_bearer_token_length,
            )
            claims = broker.verifier.verify(token)
            _enforce_identity_rate_limit(broker, request, claims, requested)
            capabilities = authorize_capabilities(
                broker.policy,
                requested,
                claims,
            )
            secrets = broker.secret_store.resolve_capabilities(capabilities)
        except AuthenticationError as exc:
            _log_denial(
                broker,
                request,
                event="authentication_denied",
                requested=requested,
                failure_class=exc.reason,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid credentials",
            ) from exc
        except AuthorizationError as exc:
            _log_denial(
                broker,
                request,
                event="authorization_denied",
                requested=requested,
                failure_class=exc.reason,
                claims=claims,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="credential capabilities are not available",
            ) from exc
        except ConfigurationError as exc:
            if exc.reason == "jwks_error":
                _log_denial(
                    broker,
                    request,
                    event="authentication_denied",
                    requested=requested,
                    failure_class=exc.reason,
                )
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="credential capabilities are temporarily unavailable",
                ) from exc
            logger.exception(
                "Broker configuration error while resolving capabilities %s",
                requested,
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="credential capabilities are temporarily unavailable",
            ) from None

        audit = audit_claims(broker.policy, claims)
        log_audit_event(
            logger,
            "credential_issued",
            endpoint=request.url.path,
            method=request.method,
            client_ip=client_ip(request, broker.settings),
            requested_capabilities=safe_requested_capabilities(requested),
            audit=audit,
        )
        response.headers["Cache-Control"] = "no-store"
        return CredentialsResponse(
            capabilities=requested,
            audit=audit,
            secrets=secrets,
        )

    if settings.enable_legacy_credentials:

        @app.post("/v1/credentials/{bundle_name}", response_model=LegacyCredentialsResponse)
        async def legacy_credentials(
            request: Request,
            response: Response,
            bundle_name: str = legacy_name_path,
            authorization: Annotated[str | None, Header(alias="Authorization")] = None,
        ) -> LegacyCredentialsResponse:
            broker: BrokerState = request.app.state.broker
            requested = [bundle_name]
            claims = None
            try:
                _enforce_ip_rate_limit(broker, request, requested)
                token = extract_bearer_token(
                    authorization,
                    max_length=broker.settings.max_bearer_token_length,
                )
                claims = broker.verifier.verify(token)
                _enforce_identity_rate_limit(broker, request, claims, requested)
                capabilities = authorize_capabilities(broker.policy, requested, claims)
                secrets = broker.secret_store.resolve_capabilities(capabilities)
            except AuthenticationError as exc:
                _log_denial(
                    broker,
                    request,
                    event="authentication_denied",
                    requested=requested,
                    failure_class=exc.reason,
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="invalid credentials",
                ) from exc
            except AuthorizationError as exc:
                _log_denial(
                    broker,
                    request,
                    event="authorization_denied",
                    requested=requested,
                    failure_class=exc.reason,
                    claims=claims,
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="credential bundle is not available",
                ) from exc
            except ConfigurationError as exc:
                if exc.reason == "jwks_error":
                    _log_denial(
                        broker,
                        request,
                        event="authentication_denied",
                        requested=requested,
                        failure_class=exc.reason,
                    )
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="credential bundle is temporarily unavailable",
                    ) from exc
                logger.exception(
                    "Broker configuration error while resolving legacy credential %s",
                    bundle_name,
                )
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="credential bundle is temporarily unavailable",
                ) from None

            audit = audit_claims(broker.policy, claims)
            log_audit_event(
                logger,
                "legacy_credential_issued",
                endpoint=request.url.path,
                method=request.method,
                client_ip=client_ip(request, broker.settings),
                requested_capabilities=safe_requested_capabilities(requested),
                audit=audit,
            )
            response.headers["Cache-Control"] = "no-store"
            return LegacyCredentialsResponse(bundle=bundle_name, audit=audit, secrets=secrets)

    return app


def _enforce_ip_rate_limit(
    broker: BrokerState,
    request: Request,
    requested: list[str],
) -> None:
    if not broker.settings.rate_limit_enabled:
        return
    ip = client_ip(request, broker.settings)
    key = f"ip:{ip}"
    if broker.ip_rate_limiter.allow(key, limit=broker.settings.rate_limit_ip_per_minute):
        return
    _log_denial(
        broker,
        request,
        event="rate_limited",
        requested=requested,
        failure_class="ip_rate_limited",
    )
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="too many requests",
    )


def _enforce_identity_rate_limit(
    broker: BrokerState,
    request: Request,
    claims: dict,
    requested: list[str],
) -> None:
    if not broker.settings.rate_limit_enabled:
        return
    identity = claims.get("repository_id") or claims.get("repository") or claims.get("sub")
    if not isinstance(identity, str) or not identity:
        identity = "unknown"
    key = f"identity:{identity}"
    if broker.identity_rate_limiter.allow(
        key,
        limit=broker.settings.rate_limit_identity_per_minute,
    ):
        return
    _log_denial(
        broker,
        request,
        event="rate_limited",
        requested=requested,
        failure_class="identity_rate_limited",
        claims=claims,
    )
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="too many requests",
    )


def _log_denial(
    broker: BrokerState,
    request: Request,
    *,
    event: str,
    requested: list[str],
    failure_class: str,
    claims: dict | None = None,
) -> None:
    fields = {
        "endpoint": request.url.path,
        "method": request.method,
        "client_ip": client_ip(request, broker.settings),
        "requested_capabilities": safe_requested_capabilities(requested),
        "failure_class": failure_class,
    }
    if claims is not None:
        fields["audit"] = safe_verified_claims(claims)
    log_audit_event(logger, event, **fields)
