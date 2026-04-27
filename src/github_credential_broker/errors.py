from __future__ import annotations


class BrokerError(Exception):
    """Base broker exception."""

    default_reason = "broker_error"

    def __init__(self, message: str = "", *, reason: str | None = None) -> None:
        super().__init__(message)
        self.reason = reason or self.default_reason


class AuthenticationError(BrokerError):
    """Request authentication failed."""

    default_reason = "invalid_jwt"


class AuthorizationError(BrokerError):
    """Authenticated identity is not allowed to access requested credentials."""

    default_reason = "not_allowed"


class ConfigurationError(BrokerError):
    """Broker policy or environment is invalid."""

    default_reason = "configuration_error"
