from __future__ import annotations


class BrokerError(Exception):
    """Base broker exception."""


class AuthenticationError(BrokerError):
    """Request authentication failed."""


class AuthorizationError(BrokerError):
    """Authenticated identity is not allowed to access requested credentials."""


class ConfigurationError(BrokerError):
    """Broker policy or environment is invalid."""
