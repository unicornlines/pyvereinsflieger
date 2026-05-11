"""Time-based One-Time Password (TOTP) generation per RFC 6238.

The Vereinsflieger 2FA flow expects a 6-digit code from a TOTP authenticator
(such as Google Authenticator, Authy or 1Password). When the shared secret is
known to the program, it can be passed to :class:`Vereinsflieger.Client` (via
the ``totp_secret`` keyword or :func:`make_totp_provider`) so that codes are
generated automatically on each login.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from collections.abc import Callable
from typing import Final, Literal

type HashAlgorithm = Literal["sha1", "sha256", "sha512"]

DEFAULT_DIGITS: Final = 6
DEFAULT_PERIOD: Final = 30
DEFAULT_ALGORITHM: Final[HashAlgorithm] = "sha1"


def _decode_base32_secret(secret: str) -> bytes:
    """Decode a (possibly whitespace-padded, unpadded) base32 TOTP secret.

    Authenticator apps and QR codes commonly produce base32 strings without
    padding, mixed-case, or with embedded spaces. This helper normalises all
    of those before decoding.
    """
    cleaned = (
        secret.strip().replace(" ", "").replace("-", "").rstrip("=").upper()
    )
    if not cleaned:
        raise ValueError("TOTP secret is empty")
    padding = (-len(cleaned)) % 8
    try:
        return base64.b32decode(cleaned + "=" * padding)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError(f"Invalid base32 TOTP secret: {exc}") from exc


def generate_totp(
    secret: str,
    *,
    digits: int = DEFAULT_DIGITS,
    period: int = DEFAULT_PERIOD,
    algorithm: HashAlgorithm = DEFAULT_ALGORITHM,
    timestamp: float | None = None,
) -> str:
    """Generate a TOTP code as a zero-padded string of ``digits`` digits.

    Parameters
    ----------
    secret:
        The base32-encoded shared secret (case- and padding-insensitive).
    digits:
        Number of digits in the resulting code. Vereinsflieger uses 6.
    period:
        Time-step in seconds. Standard TOTP uses 30.
    algorithm:
        HMAC hash algorithm. Vereinsflieger uses SHA-1 (the TOTP default).
    timestamp:
        Unix timestamp to compute the code for. Defaults to ``time.time()``.

    Returns
    -------
    str
        The TOTP code, left-zero-padded to ``digits`` characters.

    Raises
    ------
    ValueError
        If the secret is not valid base32 or parameters are out of range.
    """
    if digits < 1 or digits > 10:
        raise ValueError(f"digits must be between 1 and 10, got {digits}")
    if period < 1:
        raise ValueError(f"period must be a positive integer, got {period}")
    if algorithm not in ("sha1", "sha256", "sha512"):
        raise ValueError(
            f"algorithm must be sha1/sha256/sha512, got {algorithm!r}"
        )

    key = _decode_base32_secret(secret)
    ts = time.time() if timestamp is None else timestamp
    counter = int(ts) // period
    digest = hmac.new(
        key,
        struct.pack(">Q", counter),
        getattr(hashlib, algorithm),
    ).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10**digits)).zfill(digits)


def make_totp_provider(
    secret: str,
    *,
    digits: int = DEFAULT_DIGITS,
    period: int = DEFAULT_PERIOD,
    algorithm: HashAlgorithm = DEFAULT_ALGORITHM,
) -> Callable[[], str]:
    """Return a zero-argument callable that yields fresh TOTP codes on each call.

    Pass the returned callable as :class:`Vereinsflieger.Client`'s
    ``two_factor_provider`` to enable transparent 2FA handling, or supply
    ``totp_secret`` to the constructor for the same effect.
    """
    # Validate the secret eagerly so an invalid secret blows up at
    # configuration time rather than during a failed login.
    _decode_base32_secret(secret)

    def _provider() -> str:
        return generate_totp(
            secret, digits=digits, period=period, algorithm=algorithm
        )

    return _provider
