"""Shared pytest fixtures for the Vereinsflieger client tests."""

from __future__ import annotations

from typing import Any
from collections.abc import Iterator

import pytest
import responses

from pyvereinsflieger import Client


TEST_HOST = "https://test.vereinsflieger.invalid"
TEST_TOKEN = "TOKEN-1234567890"
TEST_APPKEY = "TESTAPPKEY"


@pytest.fixture
def mocked_responses() -> Iterator[responses.RequestsMock]:
    """Activate the ``responses`` mock for a single test."""
    with responses.RequestsMock() as rsps:
        yield rsps


@pytest.fixture
def stub_accesstoken(mocked_responses: responses.RequestsMock) -> str:
    """Stub the anonymous accesstoken endpoint."""
    mocked_responses.add(
        responses.GET,
        f"{TEST_HOST}/interface/rest/auth/accesstoken",
        json={"accesstoken": TEST_TOKEN, "httpstatuscode": 200},
        status=200,
    )
    return TEST_TOKEN


@pytest.fixture
def client(stub_accesstoken: str) -> Client:
    """A client that has already obtained an access token but is not logged in."""
    return Client(host=TEST_HOST, appkey=TEST_APPKEY, two_factor_provider=None)


@pytest.fixture
def authed_client(
    mocked_responses: responses.RequestsMock,
    client: Client,
) -> Client:
    """A client that has logged in successfully (no 2FA)."""
    mocked_responses.add(
        responses.POST,
        f"{TEST_HOST}/interface/rest/auth/signin",
        json={"httpstatuscode": 200},
        status=200,
    )
    mocked_responses.add(
        responses.POST,
        f"{TEST_HOST}/interface/rest/auth/getuser",
        json={
            "uid": 42,
            "firstname": "Test",
            "lastname": "User",
            "httpstatuscode": 200,
        },
        status=200,
    )
    client.login(username="tester", password="hunter2")
    return client


def parse_body(call: Any) -> dict[str, str]:
    """Parse a form-encoded request body into a dict (for assertions)."""
    from urllib.parse import parse_qs

    body = call.request.body or ""
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    return {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}
