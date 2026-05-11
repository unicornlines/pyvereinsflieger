"""Vereinsflieger REST API client package."""

from __future__ import annotations

from .client import DEFAULT_HOST, DEFAULT_TIMEOUT, Client
from .exceptions import (
    APIException,
    AuthenticationException,
    TwoFactorRequiredException,
    VereinsfliegerError,
)
from .totp import generate_totp, make_totp_provider

__all__ = [
    "APIException",
    "AuthenticationException",
    "Client",
    "DEFAULT_HOST",
    "DEFAULT_TIMEOUT",
    "TwoFactorRequiredException",
    "VereinsfliegerError",
    "generate_totp",
    "make_totp_provider",
]
