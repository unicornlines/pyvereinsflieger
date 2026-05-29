"""Vereinsflieger REST API client.

This module implements a synchronous client for the Vereinsflieger REST
interface as documented in the official REST-API-Spezifikation. It provides
high-level methods for every documented endpoint, transparent two-factor
authentication, and JSON parsing of responses.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable, Mapping
from datetime import date, datetime, timezone
from types import TracebackType
from typing import Any, Final, Literal, Self
from urllib.parse import quote

import requests

from .exceptions import (
    APIException,
    AuthenticationException,
    TwoFactorRequiredException,
)
from .totp import make_totp_provider

logger = logging.getLogger(__name__)

DEFAULT_HOST: Final = "https://www.vereinsflieger.de"
DEFAULT_TIMEOUT: Final = 30.0

type StartType = Literal["E", "W", "F"]
type ChargeMode = Literal[1, 2, 3, 4, 5, 7]
type Gender = Literal["m", "w", "d"]
type WorkHourStatus = Literal[1, 2, 3]
type PaymentMode = Literal[0, 1, 2, 4, 5, 6, 7, 8]
type TwoFactorProvider = Callable[[], str]
type JsonDict = dict[str, Any]
type DateLike = str | date
type DateTimeLike = str | datetime

_REDACTED_KEYS: Final = frozenset(
    {"password", "accesstoken", "appkey", "auth_secret"}
)


def _md5(value: str) -> str:
    """Return the lowercase hex MD5 digest of ``value`` (UTF-8 encoded).

    The Vereinsflieger API mandates an MD5-hashed password; this is a protocol
    requirement, not a security choice. ``usedforsecurity=False`` keeps the call
    working on FIPS-restricted Python builds, where unqualified MD5 is rejected.
    """
    return hashlib.md5(value.encode("utf-8"), usedforsecurity=False).hexdigest()


def _format_date(value: DateLike | None) -> str | None:
    """Convert ``date`` (or pass through ``str``) into ``YYYY-MM-DD``."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    return value


def _format_datetime(value: DateTimeLike | None) -> str | None:
    """Convert ``datetime`` into the API's UTC ``YYYY-MM-DD HH:MM`` format.

    The API interprets all times as UTC. Timezone-aware datetimes are
    therefore converted to UTC before formatting; naive datetimes are assumed
    to already be in UTC and formatted as-is. Strings pass through verbatim.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc)
        return value.strftime("%Y-%m-%d %H:%M")
    return value


def _drop_none(mapping: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of ``mapping`` with ``None`` values removed."""
    return {k: v for k, v in mapping.items() if v is not None}


def _strip_status(payload: JsonDict) -> JsonDict:
    """Return a copy of ``payload`` with the ``httpstatuscode`` key removed."""
    return {k: v for k, v in payload.items() if k != "httpstatuscode"}


def _records(payload: JsonDict) -> list[Any]:
    """Extract the record list from a Vereinsflieger ``list`` response.

    List endpoints return ``{"0": rec, "1": rec, ..., "httpstatuscode": 200}``.
    This helper returns just the records in their original order.
    """
    return [v for k, v in payload.items() if k != "httpstatuscode"]


def _redact(payload: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Return a debug-safe copy of ``payload`` with secrets replaced."""
    if payload is None:
        return None
    return {k: ("<redacted>" if k in _REDACTED_KEYS else v) for k, v in payload.items()}


def _safe_json(response: requests.Response) -> JsonDict:
    """Parse ``response`` as JSON, returning an empty dict on failure."""
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {"data": body}


def _interactive_2fa_provider() -> str:
    """Default two-factor provider: prompt stdin until a 6-digit code is entered."""
    while True:
        code = input("Please enter your 6-digit 2FA code: ").strip()
        if code.isdigit() and len(code) == 6:
            return code
        print("Invalid format. Please enter exactly 6 digits.")


class Client:
    """Synchronous REST client for the Vereinsflieger API.

    The constructor immediately requests an access token (anonymous call).
    Call :meth:`login` before invoking any authenticated endpoint. The client
    can be used as a context manager — on exit it will attempt to log out
    and close its HTTP session.

    Parameters
    ----------
    host:
        Base URL of the API. Defaults to ``https://www.vereinsflieger.de``.
        Flightcenter Plus customers should use ``https://www.flightcenterplus.de``.
    timeout:
        Per-request timeout in seconds.
    appkey:
        Application key. May also be provided per call to :meth:`login`.
    session:
        Optional pre-configured :class:`requests.Session`. If omitted, a new
        session is created and closed by the client.
    two_factor_provider:
        Callable invoked when the API signals that 2FA is required. Defaults
        to an interactive stdin prompt. Pass a custom callable to source the
        code from a UI, secrets manager, TOTP generator, etc.
    totp_secret:
        Convenience shorthand for ``two_factor_provider=make_totp_provider(
        totp_secret)``. The base32-encoded TOTP shared secret is stored on the
        client and used to derive fresh 6-digit codes whenever the API signals
        that 2FA is required. Mutually exclusive with ``two_factor_provider``.

    Examples
    --------
    >>> with Client(appkey="APPKEY", totp_secret="JBSWY3DPEHPK3PXP") as vf:
    ...     vf.login(username="alice", password="hunter2")
    ...     for flight in vf.list_my_flights(count=10):
    ...         print(flight["callsign"])
    """

    BASE_PATH: Final = "interface/rest"

    def __init__(
        self,
        *,
        host: str = DEFAULT_HOST,
        timeout: float = DEFAULT_TIMEOUT,
        appkey: str | None = None,
        session: requests.Session | None = None,
        two_factor_provider: TwoFactorProvider | None = _interactive_2fa_provider,
        totp_secret: str | None = None,
    ) -> None:
        if totp_secret is not None:
            if two_factor_provider is not _interactive_2fa_provider:
                raise ValueError(
                    "totp_secret and two_factor_provider are mutually exclusive"
                )
            two_factor_provider = make_totp_provider(totp_secret)
        self.host = host.rstrip("/")
        self.timeout = timeout
        self.appkey = appkey
        self.two_factor_provider = two_factor_provider
        self._owns_session = session is None
        self._session = session or requests.Session()
        self._access_token: str | None = None
        self._user_information: JsonDict | None = None
        try:
            self._fetch_access_token()
        except Exception:
            if self._owns_session:
                self._session.close()
            raise

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------
    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._user_information is not None:
            try:
                self.logout()
            except Exception:  # noqa: BLE001 — logout is best-effort on exit
                logger.exception("Logout during context exit failed")
        if self._owns_session:
            self._session.close()

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------
    @property
    def access_token(self) -> str:
        """The active access token. Raises if no token has been obtained yet."""
        if self._access_token is None:
            raise AuthenticationException(
                "No access token available; client is not initialised."
            )
        return self._access_token

    @property
    def user_information(self) -> JsonDict | None:
        """User information captured at login (``None`` until logged in)."""
        return self._user_information

    @property
    def is_authenticated(self) -> bool:
        """Whether :meth:`login` has been called successfully."""
        return self._user_information is not None

    # ------------------------------------------------------------------
    # Low-level HTTP helpers
    # ------------------------------------------------------------------
    def _build_url(self, *segments: object) -> str:
        """Build a fully-qualified URL by URL-escaping each path segment."""
        parts = [quote(str(s), safe="") for s in segments]
        return f"{self.host}/{self.BASE_PATH}/{'/'.join(parts)}"

    def _redact_url(self, url: str) -> str:
        """Mask the access token if it appears as a path segment (e.g. signout)."""
        token = self._access_token
        if not token:
            return url
        return url.replace(quote(token, safe=""), "<redacted>")

    def _request(
        self,
        method: str,
        *segments: object,
        params: Mapping[str, Any] | None = None,
        data: Mapping[str, Any] | None = None,
        authenticated: bool = True,
        expected_status: tuple[int, ...] = (200,),
    ) -> requests.Response:
        """Issue an HTTP request and return the raw :class:`requests.Response`.

        Authenticated calls automatically include the access token in ``data``
        for POST/PUT/DELETE or ``params`` for GET. Non-200 status codes raise
        a translated :class:`VereinsfliegerError`.
        """
        url = self._build_url(*segments)
        params = dict(params) if params else None
        data = dict(data) if data else None

        if authenticated:
            token = {"accesstoken": self.access_token}
            if method.upper() in {"GET", "DELETE"}:
                params = {**token, **(params or {})}
            else:
                data = {**token, **(data or {})}

        logger.debug(
            "%s %s params=%s data=%s",
            method,
            self._redact_url(url),
            _redact(params),
            _redact(data),
        )
        try:
            response = self._session.request(
                method,
                url,
                params=params,
                data=data,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise APIException(f"Network error contacting {url}: {exc}") from exc

        if response.status_code not in expected_status:
            self._raise_for_response(response)
        return response

    def _request_json(
        self,
        method: str,
        *segments: object,
        params: Mapping[str, Any] | None = None,
        data: Mapping[str, Any] | None = None,
        authenticated: bool = True,
    ) -> JsonDict:
        """Issue a request and return the parsed JSON payload."""
        response = self._request(
            method, *segments, params=params, data=data, authenticated=authenticated
        )
        try:
            payload = response.json()
        except ValueError as exc:
            raise APIException(
                f"Expected JSON response from {response.url} but got: {response.text!r}"
            ) from exc
        if not isinstance(payload, dict):
            raise APIException(
                f"Expected JSON object from {response.url} but got: {payload!r}"
            )
        return payload

    def _request_record(
        self,
        method: str,
        *segments: object,
        params: Mapping[str, Any] | None = None,
        data: Mapping[str, Any] | None = None,
        authenticated: bool = True,
    ) -> JsonDict:
        """Return a single record (``httpstatuscode`` stripped)."""
        return _strip_status(
            self._request_json(
                method,
                *segments,
                params=params,
                data=data,
                authenticated=authenticated,
            )
        )

    def _request_list(
        self,
        method: str,
        *segments: object,
        params: Mapping[str, Any] | None = None,
        data: Mapping[str, Any] | None = None,
        authenticated: bool = True,
    ) -> list[Any]:
        """Return a list of records (``httpstatuscode`` stripped)."""
        return _records(
            self._request_json(
                method,
                *segments,
                params=params,
                data=data,
                authenticated=authenticated,
            )
        )

    def _raise_for_response(self, response: requests.Response) -> None:
        """Translate non-success status codes into a typed exception."""
        body = _safe_json(response)
        message = body.get("error") or response.text or f"HTTP {response.status_code}"
        match response.status_code:
            case 400:
                raise APIException(f"Bad request: {message}")
            case 401:
                raise AuthenticationException(f"Unauthorized: {message}")
            case 403:
                raise AuthenticationException(f"Forbidden: {message}")
            case 404:
                raise APIException(f"Not found: {message}")
            case _:
                raise APIException(
                    f"HTTP {response.status_code} from API: {message}"
                )

    # ==================================================================
    # 2. Authentication
    # ==================================================================
    def _fetch_access_token(self) -> None:
        """Request an anonymous access token from ``auth/accesstoken``."""
        url = self._build_url("auth", "accesstoken")
        try:
            response = self._session.get(url, timeout=self.timeout)
        except requests.RequestException as exc:
            raise APIException(
                f"Network error obtaining access token: {exc}"
            ) from exc
        if response.status_code != 200:
            raise AuthenticationException(
                f"Failed to obtain access token (HTTP {response.status_code})"
            )
        body = _safe_json(response)
        token = body.get("accesstoken")
        if not token:
            raise AuthenticationException(
                "Access token endpoint returned no `accesstoken` field."
            )
        self._access_token = token
        logger.debug("Obtained access token")

    def login(
        self,
        username: str,
        password: str,
        appkey: str | None = None,
        *,
        cid: int | None = None,
        auth_secret: str | None = None,
    ) -> JsonDict:
        """Authenticate a user against the Vereinsflieger API.

        The password is MD5-hashed before transmission as required by the API.

        Parameters
        ----------
        username:
            The user's login name.
        password:
            The user's plaintext password. It is hashed locally with MD5.
        appkey:
            The application key (Stammdaten → Einstellungen → REST Interface).
            Falls back to the value passed to :meth:`__init__`.
        cid:
            Optional club id, required if the user is a member of multiple
            clubs.
        auth_secret:
            Optional pre-supplied 2FA code. If omitted and the account
            requires 2FA, the configured ``two_factor_provider`` is invoked
            once and the request retried.

        Returns
        -------
        dict
            The authenticated user's information (same payload as
            :meth:`get_user`).

        Raises
        ------
        AuthenticationException
            On invalid credentials or transport errors.
        TwoFactorRequiredException
            When the account requires 2FA but no provider is configured.
        """
        resolved_appkey = appkey or self.appkey
        if not resolved_appkey:
            raise ValueError(
                "appkey must be provided either to login() or the Client constructor"
            )

        payload: dict[str, Any] = {
            "accesstoken": self.access_token,
            "username": username,
            "password": _md5(password),
            "appkey": resolved_appkey,
        }
        if cid is not None:
            payload["cid"] = cid
        if auth_secret is not None:
            payload["auth_secret"] = auth_secret

        response = self._post_signin(payload)

        if response.status_code == 403 and auth_secret is None:
            body = _safe_json(response)
            if int(body.get("need_2fa", 0)) == 1:
                if self.two_factor_provider is None:
                    raise TwoFactorRequiredException(
                        "Two-factor authentication is required but no provider"
                        " is configured."
                    )
                logger.info("Account requires 2FA; invoking provider")
                payload["auth_secret"] = self.two_factor_provider()
                response = self._post_signin(payload)

        if response.status_code != 200:
            body = _safe_json(response)
            message = (
                body.get("error") or response.text or f"HTTP {response.status_code}"
            )
            raise AuthenticationException(f"Login failed: {message}")

        logger.info("Login to Vereinsflieger successful")
        self._user_information = self.get_user()
        return self._user_information

    def _post_signin(self, payload: Mapping[str, Any]) -> requests.Response:
        """Send the actual ``auth/signin`` POST without status-code raising."""
        url = self._build_url("auth", "signin")
        logger.debug("POST %s data=%s", url, _redact(payload))
        try:
            return self._session.post(
                url, data=dict(payload), timeout=self.timeout
            )
        except requests.RequestException as exc:
            raise APIException(
                f"Network error during sign-in: {exc}"
            ) from exc

    def logout(self) -> None:
        """Terminate the current session.

        The access token is encoded in the URL per the API specification. The
        local user information is cleared regardless of the API response.
        """
        if self._access_token is None:
            return
        try:
            self._request(
                "DELETE",
                "auth",
                "signout",
                self._access_token,
                authenticated=False,
            )
            logger.info("Logout successful")
        finally:
            self._user_information = None

    def get_user(self) -> JsonDict:
        """Return information about the currently authenticated user."""
        return self._request_record("POST", "auth", "getuser")

    # ==================================================================
    # 3. Flights
    # ==================================================================
    def add_flight(
        self,
        callsign: str,
        *,
        pilotname: str | None = None,
        uidpilot: int | None = None,
        attendantname: str | None = None,
        uidattendant: int | None = None,
        attendantname2: str | None = None,
        uidattendant2: int | None = None,
        attendantname3: str | None = None,
        uidattendant3: int | None = None,
        starttype: StartType | None = None,
        departuretime: DateTimeLike | None = None,
        departurelocation: str | None = None,
        arrivaltime: DateTimeLike | None = None,
        arrivallocation: str | None = None,
        flighttime: int | None = None,
        landingcount: int | None = None,
        ftid: int | None = None,
        km: int | None = None,
        chargemode: ChargeMode | None = None,
        uidcharge: int | None = None,
        comment: str | None = None,
        towcallsign: str | None = None,
        towpilotname: str | None = None,
        towuidpilot: int | None = None,
        towtime: int | None = None,
        towheight: int | None = None,
        offblock: str | None = None,
        onblock: str | None = None,
        blocktime: int | None = None,
        motorstart: str | float | None = None,
        motorend: str | float | None = None,
        wid: int | None = None,
        uidwinch: int | None = None,
        uidfi: int | None = None,
        **extra: Any,
    ) -> JsonDict:
        """Create a new flight entry.

        Only ``callsign`` is required. All other parameters mirror the API
        specification — see the official documentation for semantics. Any
        keyword in ``extra`` is forwarded verbatim, useful when the API gains
        new fields.
        """
        payload = _drop_none(
            {
                "callsign": callsign,
                "pilotname": pilotname,
                "uidpilot": uidpilot,
                "attendantname": attendantname,
                "uidattendant": uidattendant,
                "attendantname2": attendantname2,
                "uidattendant2": uidattendant2,
                "attendantname3": attendantname3,
                "uidattendant3": uidattendant3,
                "starttype": starttype,
                "departuretime": _format_datetime(departuretime),
                "departurelocation": departurelocation,
                "arrivaltime": _format_datetime(arrivaltime),
                "arrivallocation": arrivallocation,
                "flighttime": flighttime,
                "landingcount": landingcount,
                "ftid": ftid,
                "km": km,
                "chargemode": chargemode,
                "uidcharge": uidcharge,
                "comment": comment,
                "towcallsign": towcallsign,
                "towpilotname": towpilotname,
                "towuidpilot": towuidpilot,
                "towtime": towtime,
                "towheight": towheight,
                "offblock": offblock,
                "onblock": onblock,
                "blocktime": blocktime,
                "motorstart": motorstart,
                "motorend": motorend,
                "wid": wid,
                "uidwinch": uidwinch,
                "uidfi": uidfi,
                **extra,
            }
        )
        return self._request_record("POST", "flight", "add", data=payload)

    def edit_flight(self, flid: int, **fields: Any) -> JsonDict:
        """Edit an existing flight identified by ``flid``.

        Accepts the same field names as :meth:`add_flight`. Datetime/date
        values are auto-formatted; ``None`` values are skipped.
        """
        if "departuretime" in fields:
            fields["departuretime"] = _format_datetime(fields["departuretime"])
        if "arrivaltime" in fields:
            fields["arrivaltime"] = _format_datetime(fields["arrivaltime"])
        return self._request_record(
            "PUT", "flight", "edit", flid, data=_drop_none(fields)
        )

    def delete_flight(self, flid: int) -> None:
        """Delete the flight identified by ``flid``."""
        self._request("DELETE", "flight", "delete", flid)

    def join_tow_flights(self, flid: int, flidtow: int) -> None:
        """Link a glider flight (``flid``) with its tow flight (``flidtow``)."""
        self._request(
            "PUT",
            "flight",
            "jointowflights",
            data={"flid": flid, "flidtow": flidtow},
        )

    def get_flight(self, flid: int) -> JsonDict:
        """Return a single flight by its id."""
        return self._request_record("POST", "flight", "get", flid)

    def list_flights_today(self) -> list[JsonDict]:
        """Return all flights with today's date."""
        return self._request_list("POST", "flight", "list", "today")

    def list_flights_by_date(self, dateparam: DateLike) -> list[JsonDict]:
        """Return all flights for a single date (``YYYY-MM-DD``)."""
        return self._request_list(
            "POST",
            "flight",
            "list",
            "date",
            data={"dateparam": _format_date(dateparam)},
        )

    def list_flights_by_plane(
        self, callsign: str, count: int = 100
    ) -> list[JsonDict]:
        """Return the ``count`` most recent flights for ``callsign`` (max 100)."""
        return self._request_list(
            "POST",
            "flight",
            "list",
            "plane",
            data={"callsign": callsign, "count": count},
        )

    def list_my_flights(self, count: int = 100) -> list[JsonDict]:
        """Return the authenticated user's ``count`` most recent flights (max 1000)."""
        return self._request_list(
            "POST", "flight", "list", "myflights", data={"count": count}
        )

    def list_flights_by_user(self, uid: int, count: int = 100) -> list[JsonDict]:
        """Return the ``count`` most recent flights for user ``uid`` (max 100)."""
        return self._request_list(
            "POST",
            "flight",
            "list",
            "user",
            data={"uid": uid, "count": count},
        )

    def list_modified_flights(self, days: int) -> list[JsonDict]:
        """Return flights modified in the last ``days`` days (1–28)."""
        return self._request_list(
            "POST", "flight", "list", "modified", data={"days": days}
        )

    def list_flights_in_daterange(
        self, date_from: DateLike, date_to: DateLike
    ) -> list[JsonDict]:
        """Return all flights with a date in ``[date_from, date_to]``."""
        return self._request_list(
            "POST",
            "flight",
            "list",
            "daterange",
            data={
                "datefrom": _format_date(date_from),
                "dateto": _format_date(date_to),
            },
        )

    # ==================================================================
    # 4. Calendar
    # ==================================================================
    def list_public_calendar(self, hpaccesscode: str) -> list[JsonDict]:
        """Return public calendar entries.

        This endpoint does not require authentication; the access token is
        not transmitted.
        """
        return self._request_list(
            "POST",
            "calendar",
            "list",
            "public",
            data={"hpaccesscode": hpaccesscode},
            authenticated=False,
        )

    def list_my_calendar(self) -> list[JsonDict]:
        """Return the current user's calendar entries (ICS-style)."""
        return self._request_list("GET", "calendar", "list", "mycalendar")

    def list_appointments(
        self, date_from: DateLike, date_to: DateLike
    ) -> list[JsonDict]:
        """Return appointments with a start date in ``[date_from, date_to]``."""
        return self._request_list(
            "GET",
            "calendar",
            "list",
            params={
                "datefrom": _format_date(date_from),
                "dateto": _format_date(date_to),
            },
        )

    def add_appointment(
        self,
        title: str,
        date_from: DateTimeLike,
        date_to: DateTimeLike,
        *,
        exthomepage: int | None = None,
        location: str | None = None,
        comment: str | None = None,
        appointmenturl: str | None = None,
    ) -> JsonDict:
        """Create a new calendar appointment."""
        return self._request_record(
            "POST",
            "calendar",
            "add",
            data=_drop_none(
                {
                    "title": title,
                    "datefrom": _format_datetime(date_from),
                    "dateto": _format_datetime(date_to),
                    "exthomepage": exthomepage,
                    "location": location,
                    "comment": comment,
                    "appointmenturl": appointmenturl,
                }
            ),
        )

    def edit_appointment(
        self,
        apoid: int,
        date_from: DateTimeLike,
        date_to: DateTimeLike,
        *,
        title: str | None = None,
        exthomepage: int | None = None,
        location: str | None = None,
        comment: str | None = None,
        appointmenturl: str | None = None,
    ) -> JsonDict:
        """Edit an existing appointment by its ``apoid``."""
        return self._request_record(
            "PUT",
            "calendar",
            "edit",
            apoid,
            data=_drop_none(
                {
                    "datefrom": _format_datetime(date_from),
                    "dateto": _format_datetime(date_to),
                    "title": title,
                    "exthomepage": exthomepage,
                    "location": location,
                    "comment": comment,
                    "appointmenturl": appointmenturl,
                }
            ),
        )

    def delete_appointment(self, apoid: int) -> None:
        """Delete an appointment by its ``apoid``."""
        self._request("DELETE", "calendar", "delete", apoid)

    # ==================================================================
    # 5. Members
    # ==================================================================
    def list_users(self) -> list[JsonDict]:
        """Return the club's member list (requires ``edit member data`` right)."""
        return self._request_list("POST", "user", "list")

    # ==================================================================
    # 6. Reservations
    # ==================================================================
    def list_active_reservations(self) -> list[JsonDict]:
        """Return currently active reservations."""
        return self._request_list("POST", "reservation", "list", "active")

    # ==================================================================
    # 7. Maintenance
    # ==================================================================
    def get_airplane_maintenance(self, callsign: str) -> JsonDict:
        """Return current airframe times for the aircraft ``callsign``."""
        return self._request_record(
            "POST",
            "maintenance",
            "airplane",
            callsign,
            data={"callsign": callsign},
        )

    # ==================================================================
    # 8. Accounting / Bookings
    # ==================================================================
    def add_booking(
        self,
        *,
        bookingdate: DateLike,
        value: float,
        debitaccount: str,
        creditaccount: str,
        bookingtext: str,
        salestax: float | None = None,
        taxaccount: str | None = None,
        accountreference: str | None = None,
        accountreferenceid: int | None = None,
        costtype: str | None = None,
        spid: int | None = None,
    ) -> JsonDict:
        """Create a new accounting booking (requires bookkeeping mode v2)."""
        if value <= 0:
            raise ValueError("value must be greater than 0")
        return self._request_record(
            "POST",
            "account",
            "add",
            data=_drop_none(
                {
                    "bookingdate": _format_date(bookingdate),
                    "value": value,
                    "salestax": salestax,
                    "debitaccount": debitaccount,
                    "creditaccount": creditaccount,
                    "taxaccount": taxaccount,
                    "accountreference": accountreference,
                    "accountreferenceid": accountreferenceid,
                    "bookingtext": bookingtext,
                    "costtype": costtype,
                    "spid": spid,
                }
            ),
        )

    def edit_booking(self, adid: int, **fields: Any) -> JsonDict:
        """Edit an existing booking by ``adid``."""
        if "bookingdate" in fields:
            fields["bookingdate"] = _format_date(fields["bookingdate"])
        return self._request_record(
            "PUT", "account", "edit", adid, data=_drop_none(fields)
        )

    def get_booking(self, adid: int) -> JsonDict:
        """Return a single booking by its ``adid``."""
        return self._request_record("POST", "account", "get", adid)

    def list_bookings_today(self) -> list[JsonDict]:
        """Return all bookings with today's booking date."""
        return self._request_list("POST", "account", "list", "today")

    def list_bookings_year(self, year: int) -> list[JsonDict]:
        """Return all bookings made in the given accounting ``year``."""
        return self._request_list(
            "POST", "account", "list", "year", data={"year": year}
        )

    def list_bookings_in_daterange(
        self, date_from: DateLike, date_to: DateLike
    ) -> list[JsonDict]:
        """Return all bookings within ``[date_from, date_to]``."""
        return self._request_list(
            "POST",
            "account",
            "list",
            "daterange",
            data={
                "datefrom": _format_date(date_from),
                "dateto": _format_date(date_to),
            },
        )

    # ==================================================================
    # 9. Work hours
    # ==================================================================
    def list_workhours(
        self, date_from: DateLike, date_to: DateLike
    ) -> list[JsonDict]:
        """Return work hour records within ``[date_from, date_to]``."""
        return self._request_list(
            "POST",
            "workhours",
            "list",
            "daterange",
            data={
                "datefrom": _format_date(date_from),
                "dateto": _format_date(date_to),
            },
        )

    def add_workhours(
        self,
        *,
        uid: int,
        jobdate: DateLike,
        jobtext: str,
        hours: str,
        category: int,
        timefrom: str | None = None,
        timeto: str | None = None,
        status: WorkHourStatus | None = None,
        comment: str | None = None,
    ) -> JsonDict:
        """Create a new work-hour record."""
        return self._request_record(
            "POST",
            "workhours",
            "add",
            data=_drop_none(
                {
                    "uid": uid,
                    "jobdate": _format_date(jobdate),
                    "jobtext": jobtext,
                    "hours": hours,
                    "category": category,
                    "timefrom": timefrom,
                    "timeto": timeto,
                    "status": status,
                    "comment": comment,
                }
            ),
        )

    def list_workhour_categories(self) -> list[JsonDict]:
        """Return all work-hour categories."""
        return self._request_list("POST", "workhourcategories", "list")

    # ==================================================================
    # 10. Sales (Allgemeiner Verkauf)
    # ==================================================================
    def list_articles(self) -> list[JsonDict]:
        """Return the article catalogue."""
        return self._request_list("POST", "articles", "list")

    def list_sales_in_daterange(
        self, date_from: DateLike, date_to: DateLike
    ) -> list[JsonDict]:
        """Return sales with a service date in ``[date_from, date_to]``."""
        return self._request_list(
            "POST",
            "sale",
            "list",
            "daterange",
            data={
                "datefrom": _format_date(date_from),
                "dateto": _format_date(date_to),
            },
        )

    def list_modified_sales(self, days: int) -> list[JsonDict]:
        """Return sales modified in the last ``days`` days (1–28)."""
        return self._request_list(
            "POST", "sale", "list", "modified", data={"days": days}
        )

    def list_sales_by_date(self, date_param: DateLike) -> list[JsonDict]:
        """Return sales with a service date equal to ``date_param``."""
        return self._request_list(
            "POST",
            "sale",
            "list",
            "date",
            data={"date": _format_date(date_param)},
        )

    def list_sales_today(self) -> list[JsonDict]:
        """Return sales with today's service date."""
        return self._request_list("POST", "sale", "list", "today")

    def add_sale(
        self,
        *,
        bookingdate: DateLike,
        articleid: str,
        amount: float,
        memberid: int | None = None,
        callsign: str | None = None,
        salestax: float | None = None,
        totalprice: float | None = None,
        counter: float | None = None,
        comment: str | None = None,
        costtype: str | None = None,
        caid2: int | None = None,
        spid: int | None = None,
        paymentmode: PaymentMode | None = None,
    ) -> JsonDict:
        """Record a new sale."""
        return self._request_record(
            "POST",
            "sale",
            "add",
            data=_drop_none(
                {
                    "bookingdate": _format_date(bookingdate),
                    "articleid": articleid,
                    "amount": amount,
                    "memberid": memberid,
                    "callsign": callsign,
                    "salestax": salestax,
                    "totalprice": totalprice,
                    "counter": counter,
                    "comment": comment,
                    "costtype": costtype,
                    "caid2": caid2,
                    "spid": spid,
                    "paymentmode": paymentmode,
                }
            ),
        )

    # ==================================================================
    # 11. Backup
    # ==================================================================
    def get_backup_archive(self) -> bytes:
        """Return the full data backup as raw ZIP bytes."""
        response = self._request("GET", "backup", "getzip")
        return response.content

    # ==================================================================
    # 12. Vouchers
    # ==================================================================
    def list_vouchers(self) -> list[JsonDict]:
        """Return all vouchers."""
        return self._request_list("POST", "voucher", "list")

    def add_voucher(
        self,
        *,
        voucherid: str,
        title: str,
        value: float,
        lastname: str | None = None,
        insertnewuser: int | None = None,
        comment: str | None = None,
        voucherdate: DateLike | None = None,
        gender: Gender | None = None,
        firstname: str | None = None,
        street: str | None = None,
        zipcode: str | None = None,
        town: str | None = None,
        email: str | None = None,
        phonenumber: str | None = None,
        expiredate: DateLike | None = None,
        passenger: str | None = None,
    ) -> JsonDict:
        """Create a new voucher.

        ``lastname`` becomes mandatory when ``insertnewuser`` is ``1`` because
        the API then registers the recipient as a member.
        """
        if insertnewuser == 1 and not lastname:
            raise ValueError(
                "lastname is required when insertnewuser=1 (member registration)"
            )
        return self._request_record(
            "POST",
            "voucher",
            "add",
            data=_drop_none(
                {
                    "voucherid": voucherid,
                    "title": title,
                    "value": value,
                    "lastname": lastname,
                    "insertnewuser": insertnewuser,
                    "comment": comment,
                    "voucherdate": _format_date(voucherdate),
                    "gender": gender,
                    "firstname": firstname,
                    "street": street,
                    "zipcode": zipcode,
                    "town": town,
                    "email": email,
                    "phonenumber": phonenumber,
                    "expiredate": _format_date(expiredate),
                    "passenger": passenger,
                }
            ),
        )
