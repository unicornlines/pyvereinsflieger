"""Tests for the TOTP implementation and its integration with the client."""

from __future__ import annotations

import pytest
import responses

from pyvereinsflieger import (
    Client,
    generate_totp,
    make_totp_provider,
)
from pyvereinsflieger.totp import _decode_base32_secret

from .conftest import TEST_APPKEY, TEST_HOST, TEST_TOKEN, parse_body


# RFC 6238 / RFC 4226 reference vectors. The SHA-1 secret is the ASCII string
# "12345678901234567890" which base32-encodes to GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ.
SHA1_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


class TestRfc6238Vectors:
    @pytest.mark.parametrize(
        ("timestamp", "expected"),
        [
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ],
    )
    def test_sha1_8_digit_vectors(self, timestamp: int, expected: str) -> None:
        assert (
            generate_totp(
                SHA1_SECRET, digits=8, period=30, timestamp=timestamp
            )
            == expected
        )

    @pytest.mark.parametrize(
        ("timestamp", "expected"),
        [
            (0, "755224"),
            (30, "287082"),
            (60, "359152"),
            (90, "969429"),
        ],
    )
    def test_sha1_6_digit_matches_hotp(
        self, timestamp: int, expected: str
    ) -> None:
        assert (
            generate_totp(
                SHA1_SECRET, digits=6, period=30, timestamp=timestamp
            )
            == expected
        )


class TestSecretNormalisation:
    def test_lowercase_secret_accepted(self) -> None:
        upper = generate_totp(SHA1_SECRET, timestamp=0)
        lower = generate_totp(SHA1_SECRET.lower(), timestamp=0)
        assert upper == lower

    def test_spaces_stripped(self) -> None:
        spaced = " ".join(
            SHA1_SECRET[i : i + 4] for i in range(0, len(SHA1_SECRET), 4)
        )
        assert generate_totp(spaced, timestamp=0) == generate_totp(
            SHA1_SECRET, timestamp=0
        )

    def test_hyphens_stripped(self) -> None:
        hyphenated = "-".join(
            SHA1_SECRET[i : i + 4] for i in range(0, len(SHA1_SECRET), 4)
        )
        assert generate_totp(hyphenated, timestamp=0) == generate_totp(
            SHA1_SECRET, timestamp=0
        )

    def test_unpadded_secret_accepted(self) -> None:
        unpadded = "JBSWY3DPEHPK3PXP"
        padded = unpadded + "===="
        assert generate_totp(unpadded, timestamp=0) == generate_totp(
            padded, timestamp=0
        )

    def test_empty_secret_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            _decode_base32_secret("   ")

    def test_invalid_base32_rejected(self) -> None:
        with pytest.raises(ValueError, match="base32"):
            _decode_base32_secret("not-valid-base32!@#")


class TestParameterValidation:
    def test_digits_must_be_in_range(self) -> None:
        with pytest.raises(ValueError, match="digits"):
            generate_totp(SHA1_SECRET, digits=0)
        with pytest.raises(ValueError, match="digits"):
            generate_totp(SHA1_SECRET, digits=11)

    def test_period_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="period"):
            generate_totp(SHA1_SECRET, period=0)

    def test_algorithm_must_be_supported(self) -> None:
        with pytest.raises(ValueError, match="algorithm"):
            generate_totp(SHA1_SECRET, algorithm="md5")  # type: ignore[arg-type]


class TestProviderHelper:
    def test_returns_six_digit_string_by_default(self) -> None:
        provider = make_totp_provider(SHA1_SECRET)
        code = provider()
        assert len(code) == 6
        assert code.isdigit()

    def test_validates_secret_eagerly(self) -> None:
        with pytest.raises(ValueError, match="base32"):
            make_totp_provider("not-a-valid-secret!")

    def test_produces_fresh_codes_per_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = make_totp_provider(SHA1_SECRET)
        clock = iter([0.0, 30.0, 60.0, 90.0])
        monkeypatch.setattr(
            "pyvereinsflieger.totp.time.time", lambda: next(clock)
        )
        codes = [provider() for _ in range(4)]
        assert codes == ["755224", "287082", "359152", "969429"]


class TestClientIntegration:
    def test_totp_secret_constructor_drives_2fa_login(
        self,
        mocked_responses: responses.RequestsMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mocked_responses.add(
            responses.GET,
            f"{TEST_HOST}/interface/rest/auth/accesstoken",
            json={"accesstoken": TEST_TOKEN},
            status=200,
        )
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/auth/signin",
            json={"error": "2FA required", "need_2fa": 1},
            status=403,
        )
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/auth/signin",
            json={"httpstatuscode": 200},
            status=200,
        )
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/auth/getuser",
            json={"uid": 1, "httpstatuscode": 200},
            status=200,
        )

        # Pin the clock so we know which TOTP code will be generated.
        monkeypatch.setattr("pyvereinsflieger.totp.time.time", lambda: 0.0)
        expected_code = generate_totp(SHA1_SECRET, timestamp=0.0)

        client = Client(
            host=TEST_HOST,
            appkey=TEST_APPKEY,
            totp_secret=SHA1_SECRET,
        )
        client.login("alice", "pw")

        retry_body = parse_body(mocked_responses.calls[2])
        assert retry_body["auth_secret"] == expected_code

    def test_totp_secret_and_two_factor_provider_are_mutually_exclusive(
        self,
    ) -> None:
        with pytest.raises(ValueError, match="mutually exclusive"):
            Client(
                host=TEST_HOST,
                appkey=TEST_APPKEY,
                totp_secret=SHA1_SECRET,
                two_factor_provider=lambda: "000000",
            )

    def test_invalid_totp_secret_rejected_at_construction(self) -> None:
        with pytest.raises(ValueError, match="base32"):
            Client(host=TEST_HOST, appkey=TEST_APPKEY, totp_secret="!!!")
