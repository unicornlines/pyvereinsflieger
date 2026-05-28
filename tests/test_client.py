"""Tests for the Vereinsflieger REST client."""

from __future__ import annotations

import hashlib
from datetime import date, datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest
import responses

from pyvereinsflieger import (
    APIException,
    AuthenticationException,
    Client,
    TwoFactorRequiredException,
)
from pyvereinsflieger.client import (
    _drop_none,
    _format_date,
    _format_datetime,
    _md5,
    _records,
    _redact,
    _strip_status,
)

from .conftest import TEST_APPKEY, TEST_HOST, TEST_TOKEN, parse_body


# ----------------------------------------------------------------------
# Helper unit tests
# ----------------------------------------------------------------------
class TestHelpers:
    def test_md5_matches_hashlib(self) -> None:
        assert _md5("password") == hashlib.md5(b"password").hexdigest()

    def test_md5_uses_utf8(self) -> None:
        assert _md5("Π") == hashlib.md5("Π".encode("utf-8")).hexdigest()

    def test_format_date_from_date(self) -> None:
        assert _format_date(date(2026, 5, 11)) == "2026-05-11"

    def test_format_date_from_datetime(self) -> None:
        assert _format_date(datetime(2026, 5, 11, 14, 30)) == "2026-05-11"

    def test_format_date_passthrough_str(self) -> None:
        assert _format_date("2026-05-11") == "2026-05-11"

    def test_format_date_none(self) -> None:
        assert _format_date(None) is None

    def test_format_datetime_from_datetime(self) -> None:
        assert (
            _format_datetime(datetime(2026, 5, 11, 14, 30)) == "2026-05-11 14:30"
        )

    def test_format_datetime_passthrough_str(self) -> None:
        assert _format_datetime("2026-05-11 14:30") == "2026-05-11 14:30"

    def test_format_datetime_converts_aware_to_utc(self) -> None:
        cest = timezone(timedelta(hours=2))
        aware = datetime(2026, 5, 11, 18, 30, tzinfo=cest)
        assert _format_datetime(aware) == "2026-05-11 16:30"

    def test_drop_none_filters_none(self) -> None:
        assert _drop_none({"a": 1, "b": None, "c": "x"}) == {"a": 1, "c": "x"}

    def test_drop_none_keeps_falsy(self) -> None:
        assert _drop_none({"a": 0, "b": "", "c": False}) == {
            "a": 0,
            "b": "",
            "c": False,
        }

    def test_strip_status_removes_httpstatuscode(self) -> None:
        assert _strip_status({"foo": 1, "httpstatuscode": 200}) == {"foo": 1}

    def test_records_returns_list(self) -> None:
        payload = {"0": {"a": 1}, "1": {"a": 2}, "httpstatuscode": 200}
        assert _records(payload) == [{"a": 1}, {"a": 2}]

    def test_records_empty(self) -> None:
        assert _records({"httpstatuscode": 200}) == []

    def test_redact_replaces_sensitive_keys(self) -> None:
        out = _redact({"username": "alice", "password": "secret", "appkey": "k"})
        assert out == {
            "username": "alice",
            "password": "<redacted>",
            "appkey": "<redacted>",
        }

    def test_redact_none(self) -> None:
        assert _redact(None) is None


# ----------------------------------------------------------------------
# Construction / access token
# ----------------------------------------------------------------------
class TestConstruction:
    def test_fetches_accesstoken_on_init(
        self,
        mocked_responses: responses.RequestsMock,
    ) -> None:
        mocked_responses.add(
            responses.GET,
            f"{TEST_HOST}/interface/rest/auth/accesstoken",
            json={"accesstoken": TEST_TOKEN},
            status=200,
        )
        client = Client(host=TEST_HOST, appkey=TEST_APPKEY)
        assert client.access_token == TEST_TOKEN
        assert client.is_authenticated is False
        assert client.user_information is None

    def test_strips_trailing_slash_from_host(
        self,
        mocked_responses: responses.RequestsMock,
    ) -> None:
        mocked_responses.add(
            responses.GET,
            f"{TEST_HOST}/interface/rest/auth/accesstoken",
            json={"accesstoken": TEST_TOKEN},
            status=200,
        )
        client = Client(host=f"{TEST_HOST}/", appkey=TEST_APPKEY)
        assert client.host == TEST_HOST

    def test_accesstoken_failure_raises_auth(
        self,
        mocked_responses: responses.RequestsMock,
    ) -> None:
        mocked_responses.add(
            responses.GET,
            f"{TEST_HOST}/interface/rest/auth/accesstoken",
            status=500,
        )
        with pytest.raises(AuthenticationException):
            Client(host=TEST_HOST, appkey=TEST_APPKEY)

    def test_accesstoken_missing_field_raises(
        self,
        mocked_responses: responses.RequestsMock,
    ) -> None:
        mocked_responses.add(
            responses.GET,
            f"{TEST_HOST}/interface/rest/auth/accesstoken",
            json={"httpstatuscode": 200},
            status=200,
        )
        with pytest.raises(AuthenticationException):
            Client(host=TEST_HOST, appkey=TEST_APPKEY)

    def test_accesstoken_network_error_raises_api(
        self,
        mocked_responses: responses.RequestsMock,
    ) -> None:
        import requests as _requests

        def _boom(*_args, **_kwargs):
            raise _requests.ConnectionError("network down")

        mocked_responses.add_callback(
            responses.GET,
            f"{TEST_HOST}/interface/rest/auth/accesstoken",
            callback=_boom,
        )
        with pytest.raises(APIException, match="Network error"):
            Client(host=TEST_HOST, appkey=TEST_APPKEY)


# ----------------------------------------------------------------------
# Login / 2FA / logout
# ----------------------------------------------------------------------
class TestLogin:
    def test_login_success_no_2fa(
        self,
        mocked_responses: responses.RequestsMock,
        client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/auth/signin",
            json={"httpstatuscode": 200},
            status=200,
        )
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/auth/getuser",
            json={"uid": 7, "firstname": "Alice", "httpstatuscode": 200},
            status=200,
        )
        info = client.login(username="alice", password="hunter2")
        assert info == {"uid": 7, "firstname": "Alice"}
        assert client.is_authenticated

        body = parse_body(mocked_responses.calls[1])
        assert body["username"] == "alice"
        assert body["password"] == hashlib.md5(b"hunter2").hexdigest()
        assert body["appkey"] == TEST_APPKEY
        assert body["accesstoken"] == TEST_TOKEN
        assert "auth_secret" not in body
        assert "cid" not in body

    def test_login_includes_cid(
        self,
        mocked_responses: responses.RequestsMock,
        client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/auth/signin",
            json={"httpstatuscode": 200},
            status=200,
        )
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/auth/getuser",
            json={"uid": 7, "httpstatuscode": 200},
            status=200,
        )
        client.login(username="alice", password="pw", cid=99)
        body = parse_body(mocked_responses.calls[1])
        assert body["cid"] == "99"

    def test_login_uses_constructor_appkey_when_omitted(
        self,
        mocked_responses: responses.RequestsMock,
        client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/auth/signin",
            json={"httpstatuscode": 200},
            status=200,
        )
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/auth/getuser",
            json={"httpstatuscode": 200},
            status=200,
        )
        client.login("alice", "pw")
        body = parse_body(mocked_responses.calls[1])
        assert body["appkey"] == TEST_APPKEY

    def test_login_requires_appkey(
        self,
        mocked_responses: responses.RequestsMock,
        stub_accesstoken: str,
    ) -> None:
        client = Client(host=TEST_HOST, two_factor_provider=None)
        with pytest.raises(ValueError, match="appkey"):
            client.login("alice", "pw")

    def test_login_2fa_required_triggers_provider(
        self,
        mocked_responses: responses.RequestsMock,
        client: Client,
    ) -> None:
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
            json={"uid": 7, "httpstatuscode": 200},
            status=200,
        )
        provider_calls = 0

        def provider() -> str:
            nonlocal provider_calls
            provider_calls += 1
            return "123456"

        client.two_factor_provider = provider
        client.login("alice", "pw")
        assert provider_calls == 1
        body = parse_body(mocked_responses.calls[2])
        assert body["auth_secret"] == "123456"

    def test_login_2fa_already_supplied_skips_provider(
        self,
        mocked_responses: responses.RequestsMock,
        client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/auth/signin",
            json={"httpstatuscode": 200},
            status=200,
        )
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/auth/getuser",
            json={"httpstatuscode": 200},
            status=200,
        )

        def fail() -> str:
            raise AssertionError("provider should not be called")

        client.two_factor_provider = fail
        client.login("alice", "pw", auth_secret="654321")
        body = parse_body(mocked_responses.calls[1])
        assert body["auth_secret"] == "654321"

    def test_login_invalid_credentials_raises_no_2fa(
        self,
        mocked_responses: responses.RequestsMock,
        client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/auth/signin",
            json={"error": "Invalid credentials"},
            status=403,
        )
        with pytest.raises(AuthenticationException, match="Invalid credentials"):
            client.login("alice", "wrong")

    def test_login_2fa_required_but_no_provider_raises(
        self,
        mocked_responses: responses.RequestsMock,
        client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/auth/signin",
            json={"error": "2FA required", "need_2fa": 1},
            status=403,
        )
        client.two_factor_provider = None
        with pytest.raises(TwoFactorRequiredException):
            client.login("alice", "pw")

    def test_login_2fa_retry_fails(
        self,
        mocked_responses: responses.RequestsMock,
        client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/auth/signin",
            json={"error": "2FA required", "need_2fa": 1},
            status=403,
        )
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/auth/signin",
            json={"error": "Invalid 2FA code"},
            status=403,
        )
        client.two_factor_provider = lambda: "000000"
        with pytest.raises(AuthenticationException, match="Invalid 2FA code"):
            client.login("alice", "pw")

    def test_login_network_error_raises_api(
        self,
        mocked_responses: responses.RequestsMock,
        client: Client,
    ) -> None:
        import requests as _requests

        def _boom(*_args, **_kwargs):
            raise _requests.ConnectionError("network down")

        mocked_responses.add_callback(
            responses.POST,
            f"{TEST_HOST}/interface/rest/auth/signin",
            callback=_boom,
        )
        with pytest.raises(APIException, match="Network error"):
            client.login("alice", "pw")

    def test_logout_uses_token_in_url(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.DELETE,
            f"{TEST_HOST}/interface/rest/auth/signout/{TEST_TOKEN}",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.logout()
        assert authed_client.is_authenticated is False

    def test_logout_clears_user_info_even_on_failure(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.DELETE,
            f"{TEST_HOST}/interface/rest/auth/signout/{TEST_TOKEN}",
            json={"error": "boom"},
            status=500,
        )
        with pytest.raises(APIException):
            authed_client.logout()
        assert authed_client.is_authenticated is False


# ----------------------------------------------------------------------
# Context manager
# ----------------------------------------------------------------------
class TestContextManager:
    def test_context_manager_logs_out(
        self,
        mocked_responses: responses.RequestsMock,
        stub_accesstoken: str,
    ) -> None:
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
        mocked_responses.add(
            responses.DELETE,
            f"{TEST_HOST}/interface/rest/auth/signout/{TEST_TOKEN}",
            json={"httpstatuscode": 200},
            status=200,
        )
        with Client(
            host=TEST_HOST, appkey=TEST_APPKEY, two_factor_provider=None
        ) as vf:
            vf.login("alice", "pw")
        assert mocked_responses.calls[-1].request.method == "DELETE"

    def test_context_manager_no_logout_if_never_authenticated(
        self,
        mocked_responses: responses.RequestsMock,
        stub_accesstoken: str,
    ) -> None:
        with Client(
            host=TEST_HOST, appkey=TEST_APPKEY, two_factor_provider=None
        ):
            pass
        methods = [c.request.method for c in mocked_responses.calls]
        assert "DELETE" not in methods


# ----------------------------------------------------------------------
# Flights
# ----------------------------------------------------------------------
class TestFlights:
    def test_get_flight(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/flight/get/12345",
            json={"flid": 12345, "callsign": "DEABC", "httpstatuscode": 200},
            status=200,
        )
        flight = authed_client.get_flight(12345)
        assert flight == {"flid": 12345, "callsign": "DEABC"}

    def test_list_flights_today(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/flight/list/today",
            json={
                "0": {"flid": 1, "callsign": "DEABC"},
                "1": {"flid": 2, "callsign": "DEXYZ"},
                "httpstatuscode": 200,
            },
            status=200,
        )
        result = authed_client.list_flights_today()
        assert len(result) == 2
        assert result[0]["flid"] == 1

    def test_list_my_flights_passes_count(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/flight/list/myflights",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.list_my_flights(count=250)
        body = parse_body(mocked_responses.calls[-1])
        assert body["count"] == "250"
        assert body["accesstoken"] == TEST_TOKEN

    def test_list_flights_by_plane(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/flight/list/plane",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.list_flights_by_plane("D-EABC", count=20)
        body = parse_body(mocked_responses.calls[-1])
        assert body["callsign"] == "D-EABC"
        assert body["count"] == "20"

    def test_list_flights_by_user(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/flight/list/user",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.list_flights_by_user(uid=42, count=50)
        body = parse_body(mocked_responses.calls[-1])
        assert body["uid"] == "42"
        assert body["count"] == "50"

    def test_list_modified_flights(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/flight/list/modified",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.list_modified_flights(days=7)
        body = parse_body(mocked_responses.calls[-1])
        assert body["days"] == "7"

    def test_list_flights_by_date_formats_date(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/flight/list/date",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.list_flights_by_date(date(2026, 5, 11))
        body = parse_body(mocked_responses.calls[-1])
        assert body["dateparam"] == "2026-05-11"

    def test_list_flights_in_daterange_formats_dates(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/flight/list/daterange",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.list_flights_in_daterange(
            date(2026, 1, 1), date(2026, 12, 31)
        )
        body = parse_body(mocked_responses.calls[-1])
        assert body["datefrom"] == "2026-01-01"
        assert body["dateto"] == "2026-12-31"

    def test_add_flight_minimal(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/flight/add",
            json={"flid": 99, "callsign": "DEABC", "httpstatuscode": 200},
            status=200,
        )
        result = authed_client.add_flight("DEABC")
        body = parse_body(mocked_responses.calls[-1])
        assert body["callsign"] == "DEABC"
        assert "pilotname" not in body
        assert result["flid"] == 99

    def test_add_flight_formats_datetimes(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/flight/add",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.add_flight(
            "DEABC",
            departuretime=datetime(2026, 5, 11, 14, 30),
            arrivaltime=datetime(2026, 5, 11, 15, 45),
            pilotname="Alice",
            landingcount=2,
            chargemode=2,
        )
        body = parse_body(mocked_responses.calls[-1])
        assert body["departuretime"] == "2026-05-11 14:30"
        assert body["arrivaltime"] == "2026-05-11 15:45"
        assert body["pilotname"] == "Alice"
        assert body["landingcount"] == "2"
        assert body["chargemode"] == "2"

    def test_add_flight_forwards_extra(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/flight/add",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.add_flight("DEABC", brandnewfield="value")
        body = parse_body(mocked_responses.calls[-1])
        assert body["brandnewfield"] == "value"

    def test_edit_flight(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.PUT,
            f"{TEST_HOST}/interface/rest/flight/edit/123",
            json={"flid": 123, "httpstatuscode": 200},
            status=200,
        )
        authed_client.edit_flight(
            123,
            departuretime=datetime(2026, 5, 11, 8, 0),
            comment="updated",
        )
        body = parse_body(mocked_responses.calls[-1])
        assert body["departuretime"] == "2026-05-11 08:00"
        assert body["comment"] == "updated"

    def test_delete_flight_puts_token_in_query(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.DELETE,
            f"{TEST_HOST}/interface/rest/flight/delete/55",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.delete_flight(55)
        url = mocked_responses.calls[-1].request.url
        query = parse_qs(urlparse(url).query)
        assert query["accesstoken"] == [TEST_TOKEN]

    def test_join_tow_flights(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.PUT,
            f"{TEST_HOST}/interface/rest/flight/jointowflights",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.join_tow_flights(flid=10, flidtow=11)
        body = parse_body(mocked_responses.calls[-1])
        assert body["flid"] == "10"
        assert body["flidtow"] == "11"


# ----------------------------------------------------------------------
# Calendar
# ----------------------------------------------------------------------
class TestCalendar:
    def test_list_public_calendar_unauthenticated(
        self,
        mocked_responses: responses.RequestsMock,
        client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/calendar/list/public",
            json={
                "0": {"title": "Open day"},
                "httpstatuscode": 200,
            },
            status=200,
        )
        result = client.list_public_calendar("HPCODE")
        assert result == [{"title": "Open day"}]
        body = parse_body(mocked_responses.calls[-1])
        assert body["hpaccesscode"] == "HPCODE"
        assert "accesstoken" not in body

    def test_list_my_calendar(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.GET,
            f"{TEST_HOST}/interface/rest/calendar/list/mycalendar",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.list_my_calendar()
        url = mocked_responses.calls[-1].request.url
        query = parse_qs(urlparse(url).query)
        assert query["accesstoken"] == [TEST_TOKEN]

    def test_list_appointments(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.GET,
            f"{TEST_HOST}/interface/rest/calendar/list",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.list_appointments(
            date(2026, 5, 1), date(2026, 5, 31)
        )
        query = parse_qs(urlparse(mocked_responses.calls[-1].request.url).query)
        assert query["datefrom"] == ["2026-05-01"]
        assert query["dateto"] == ["2026-05-31"]
        assert query["accesstoken"] == [TEST_TOKEN]

    def test_add_appointment(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/calendar/add",
            json={"apoid": 7, "httpstatuscode": 200},
            status=200,
        )
        authed_client.add_appointment(
            "Open day",
            datetime(2026, 5, 11, 10, 0),
            datetime(2026, 5, 11, 18, 0),
            location="EDXY",
        )
        body = parse_body(mocked_responses.calls[-1])
        assert body["title"] == "Open day"
        assert body["datefrom"] == "2026-05-11 10:00"
        assert body["dateto"] == "2026-05-11 18:00"
        assert body["location"] == "EDXY"

    def test_edit_appointment(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.PUT,
            f"{TEST_HOST}/interface/rest/calendar/edit/9",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.edit_appointment(
            9,
            datetime(2026, 5, 12, 9, 0),
            datetime(2026, 5, 12, 17, 0),
            title="Updated",
        )
        body = parse_body(mocked_responses.calls[-1])
        assert body["datefrom"] == "2026-05-12 09:00"
        assert body["dateto"] == "2026-05-12 17:00"
        assert body["title"] == "Updated"

    def test_delete_appointment(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.DELETE,
            f"{TEST_HOST}/interface/rest/calendar/delete/9",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.delete_appointment(9)
        query = parse_qs(urlparse(mocked_responses.calls[-1].request.url).query)
        assert query["accesstoken"] == [TEST_TOKEN]


# ----------------------------------------------------------------------
# Members, reservations, maintenance
# ----------------------------------------------------------------------
class TestMembersAndMisc:
    def test_list_users(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/user/list",
            json={"0": {"uid": 1}, "httpstatuscode": 200},
            status=200,
        )
        users = authed_client.list_users()
        assert users == [{"uid": 1}]

    def test_list_active_reservations(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/reservation/list/active",
            json={"0": {"prid": 1}, "httpstatuscode": 200},
            status=200,
        )
        result = authed_client.list_active_reservations()
        assert result == [{"prid": 1}]

    def test_get_airplane_maintenance(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/maintenance/airplane/D-EABC",
            json={"motortime": 1234.5, "httpstatuscode": 200},
            status=200,
        )
        result = authed_client.get_airplane_maintenance("D-EABC")
        assert result == {"motortime": 1234.5}


# ----------------------------------------------------------------------
# Bookings (accounts)
# ----------------------------------------------------------------------
class TestBookings:
    def test_add_booking(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/account/add",
            json={"adid": 1, "httpstatuscode": 200},
            status=200,
        )
        authed_client.add_booking(
            bookingdate=date(2026, 5, 11),
            value=199.99,
            debitaccount="1200",
            creditaccount="8400",
            bookingtext="Fuel",
            salestax=19.0,
        )
        body = parse_body(mocked_responses.calls[-1])
        assert body["bookingdate"] == "2026-05-11"
        assert body["value"] == "199.99"
        assert body["debitaccount"] == "1200"
        assert body["creditaccount"] == "8400"
        assert body["bookingtext"] == "Fuel"
        assert body["salestax"] == "19.0"

    def test_add_booking_rejects_nonpositive_value(
        self,
        authed_client: Client,
    ) -> None:
        with pytest.raises(ValueError, match="greater than 0"):
            authed_client.add_booking(
                bookingdate=date(2026, 5, 11),
                value=0,
                debitaccount="1200",
                creditaccount="8400",
                bookingtext="Fuel",
            )

    def test_edit_booking(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.PUT,
            f"{TEST_HOST}/interface/rest/account/edit/77",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.edit_booking(77, bookingdate=date(2026, 5, 1), value=50)
        body = parse_body(mocked_responses.calls[-1])
        assert body["bookingdate"] == "2026-05-01"
        assert body["value"] == "50"

    def test_get_booking(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/account/get/77",
            json={"adid": 77, "httpstatuscode": 200},
            status=200,
        )
        assert authed_client.get_booking(77) == {"adid": 77}

    def test_list_bookings_today(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/account/list/today",
            json={"httpstatuscode": 200},
            status=200,
        )
        assert authed_client.list_bookings_today() == []

    def test_list_bookings_year(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/account/list/year",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.list_bookings_year(2026)
        body = parse_body(mocked_responses.calls[-1])
        assert body["year"] == "2026"

    def test_list_bookings_in_daterange(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/account/list/daterange",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.list_bookings_in_daterange(
            "2026-01-01", "2026-12-31"
        )
        body = parse_body(mocked_responses.calls[-1])
        assert body["datefrom"] == "2026-01-01"
        assert body["dateto"] == "2026-12-31"


# ----------------------------------------------------------------------
# Workhours, sales, vouchers, backup
# ----------------------------------------------------------------------
class TestWorkhoursAndSales:
    def test_list_workhours(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/workhours/list/daterange",
            json={"0": {"whid": 1}, "httpstatuscode": 200},
            status=200,
        )
        result = authed_client.list_workhours(
            date(2026, 1, 1), date(2026, 12, 31)
        )
        assert result == [{"whid": 1}]

    def test_add_workhours(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/workhours/add",
            json={"whid": 1, "httpstatuscode": 200},
            status=200,
        )
        authed_client.add_workhours(
            uid=42,
            jobdate=date(2026, 5, 11),
            jobtext="hangar cleanup",
            hours="04:00",
            category=1,
            comment="spring",
        )
        body = parse_body(mocked_responses.calls[-1])
        assert body["uid"] == "42"
        assert body["jobdate"] == "2026-05-11"
        assert body["hours"] == "04:00"
        assert body["category"] == "1"

    def test_list_workhour_categories(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/workhourcategories/list",
            json={"0": {"category": 1, "name": "x"}, "httpstatuscode": 200},
            status=200,
        )
        assert authed_client.list_workhour_categories() == [
            {"category": 1, "name": "x"}
        ]

    def test_list_articles(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/articles/list",
            json={"0": {"articleid": "A1"}, "httpstatuscode": 200},
            status=200,
        )
        assert authed_client.list_articles() == [{"articleid": "A1"}]

    def test_list_sales_today(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/sale/list/today",
            json={"httpstatuscode": 200},
            status=200,
        )
        assert authed_client.list_sales_today() == []

    def test_list_sales_by_date(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/sale/list/date",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.list_sales_by_date(date(2026, 5, 11))
        body = parse_body(mocked_responses.calls[-1])
        assert body["date"] == "2026-05-11"

    def test_list_sales_in_daterange(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/sale/list/daterange",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.list_sales_in_daterange("2026-01-01", "2026-12-31")
        body = parse_body(mocked_responses.calls[-1])
        assert body["datefrom"] == "2026-01-01"
        assert body["dateto"] == "2026-12-31"

    def test_list_modified_sales(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/sale/list/modified",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.list_modified_sales(days=14)
        body = parse_body(mocked_responses.calls[-1])
        assert body["days"] == "14"

    def test_add_sale(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/sale/add",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.add_sale(
            bookingdate=date(2026, 5, 11),
            articleid="FUEL-100LL",
            amount=12.5,
            callsign="D-EABC",
        )
        body = parse_body(mocked_responses.calls[-1])
        assert body["bookingdate"] == "2026-05-11"
        assert body["articleid"] == "FUEL-100LL"
        assert body["amount"] == "12.5"
        assert body["callsign"] == "D-EABC"


class TestVouchers:
    def test_list_vouchers(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/voucher/list",
            json={"0": {"vid": 1}, "httpstatuscode": 200},
            status=200,
        )
        assert authed_client.list_vouchers() == [{"vid": 1}]

    def test_add_voucher(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/voucher/add",
            json={"vid": 1, "httpstatuscode": 200},
            status=200,
        )
        authed_client.add_voucher(
            voucherid="V123",
            title="Test flight",
            value=199.0,
            insertnewuser=1,
            lastname="Doe",
            firstname="Jane",
            expiredate=date(2027, 12, 31),
        )
        body = parse_body(mocked_responses.calls[-1])
        assert body["voucherid"] == "V123"
        assert body["title"] == "Test flight"
        assert body["insertnewuser"] == "1"
        assert body["lastname"] == "Doe"
        assert body["expiredate"] == "2027-12-31"

    def test_add_voucher_requires_lastname_when_creating_member(
        self,
        authed_client: Client,
    ) -> None:
        with pytest.raises(ValueError, match="lastname"):
            authed_client.add_voucher(
                voucherid="V123",
                title="Test",
                value=10,
                insertnewuser=1,
            )


class TestBackup:
    def test_get_backup_archive(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        zip_bytes = b"PK\x03\x04somezipcontent"
        mocked_responses.add(
            responses.GET,
            f"{TEST_HOST}/interface/rest/backup/getzip",
            body=zip_bytes,
            status=200,
            content_type="application/zip",
        )
        result = authed_client.get_backup_archive()
        assert result == zip_bytes
        query = parse_qs(urlparse(mocked_responses.calls[-1].request.url).query)
        assert query["accesstoken"] == [TEST_TOKEN]


# ----------------------------------------------------------------------
# Error translation
# ----------------------------------------------------------------------
class TestErrorTranslation:
    def test_400_raises_api_exception(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/flight/list/today",
            json={"error": "invalid input"},
            status=400,
        )
        with pytest.raises(APIException, match="invalid input"):
            authed_client.list_flights_today()

    def test_401_raises_authentication_exception(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/flight/list/today",
            json={"error": "session expired"},
            status=401,
        )
        with pytest.raises(AuthenticationException, match="session expired"):
            authed_client.list_flights_today()

    def test_403_outside_login_raises_authentication_exception(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/flight/list/today",
            status=403,
        )
        with pytest.raises(AuthenticationException):
            authed_client.list_flights_today()

    def test_non_json_response_raises_api_exception(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/flight/list/today",
            body="<html>oops</html>",
            status=200,
            content_type="text/html",
        )
        with pytest.raises(APIException, match="JSON"):
            authed_client.list_flights_today()

    def test_network_error_raises_api_exception(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        import requests as _requests

        def _boom(*_args, **_kwargs):
            raise _requests.ConnectionError("network down")

        mocked_responses.add_callback(
            responses.POST,
            f"{TEST_HOST}/interface/rest/flight/list/today",
            callback=_boom,
        )
        with pytest.raises(APIException, match="Network error"):
            authed_client.list_flights_today()


# ----------------------------------------------------------------------
# Access-token propagation
# ----------------------------------------------------------------------
class TestAccessTokenPropagation:
    def test_authenticated_post_includes_token_in_body(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.POST,
            f"{TEST_HOST}/interface/rest/user/list",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.list_users()
        body = parse_body(mocked_responses.calls[-1])
        assert body["accesstoken"] == TEST_TOKEN

    def test_authenticated_get_includes_token_in_query(
        self,
        mocked_responses: responses.RequestsMock,
        authed_client: Client,
    ) -> None:
        mocked_responses.add(
            responses.GET,
            f"{TEST_HOST}/interface/rest/calendar/list",
            json={"httpstatuscode": 200},
            status=200,
        )
        authed_client.list_appointments("2026-01-01", "2026-12-31")
        query = parse_qs(urlparse(mocked_responses.calls[-1].request.url).query)
        assert query["accesstoken"] == [TEST_TOKEN]
