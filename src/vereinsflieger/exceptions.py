"""Exception hierarchy for the Vereinsflieger REST client."""

from __future__ import annotations


class VereinsfliegerError(Exception):
    """Base class for all errors raised by the Vereinsflieger client."""


class APIException(VereinsfliegerError):
    """The API returned an unexpected response or an HTTP error."""


class AuthenticationException(VereinsfliegerError):
    """Authentication against the Vereinsflieger API failed."""


class TwoFactorRequiredException(AuthenticationException):
    """The account requires two-factor authentication and no code was supplied."""
