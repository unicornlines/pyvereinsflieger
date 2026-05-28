# vereinsflieger

A Python REST client for the [Vereinsflieger](https://www.vereinsflieger.de)
flight logbook service. It covers every endpoint of the published
`REST-API-Spezifikation` (version 2025-07-29) and handles two-factor
authentication transparently when a TOTP secret is configured.

## Features

- Complete coverage of the documented endpoints: authentication, flights,
  calendar, members, reservations, maintenance, accounting bookings, work
  hours, sales, backup, and vouchers.
- Built-in TOTP code generation (RFC 6238): supply a `totp_secret` once and
  the client answers 2FA challenges on its own.
- Typed and documented throughout, targeting modern Python (3.12+, PEP 695
  type aliases, `match`/`case`, `Self`).
- Context-manager API that logs out and closes the HTTP session on exit.
- Safe defaults: the password is MD5-hashed locally before transmission,
  credentials never appear in URL query strings, and every request has a
  timeout.

## Requirements

- Python 3.12 or newer
- [`requests`](https://pypi.org/project/requests/) 2.31+

## Installation

```bash
pip install git+https://github.com/<you>/vereinsflieger.git
```

For local development:

```bash
git clone https://github.com/<you>/vereinsflieger.git
cd vereinsflieger
pip install -e ".[dev]"
pytest
```

## Quick start

```python
from vereinsflieger import Client

with Client(appkey="YOUR_APP_KEY", totp_secret="JBSWY3DPEHPK3PXP") as vf:
    vf.login(username="alice", password="hunter2")
    for flight in vf.list_my_flights(count=20):
        print(flight["dateofflight"], flight["callsign"])
```

The client requests an anonymous access token on construction, so creating a
`Client` makes one network call. Use it as a context manager to log out and
release the session automatically.

If the account belongs to more than one club, pass `cid` to `login`. Customers
of Flightcenter Plus should set `host="https://www.flightcenterplus.de"`.

## Two-factor authentication

If 2FA is enabled on the account, choose one of the following:

- **Stored secret** — pass `totp_secret=...` to the constructor and the client
  derives a fresh 6-digit code whenever the API asks for one.
- **Custom provider** — pass `two_factor_provider=callable`, where `callable`
  returns the current code. Useful for sourcing it from a UI or a secrets
  manager. (`totp_secret` and `two_factor_provider` are mutually exclusive.)
- **One-off code** — pass `auth_secret="123456"` directly to `login`.

Without any of these, the default provider prompts for a code on stdin. Pass
`two_factor_provider=None` to raise `TwoFactorRequiredException` instead.

## Dates and times

Methods that take a date or datetime accept either an ISO-formatted string or a
Python `date` / `datetime` object. The API expects all timestamps in UTC:
timezone-aware datetimes are converted to UTC automatically, and naive
datetimes are sent unchanged (i.e. assumed to already be UTC).

## Endpoint reference

| Section | Methods |
| --- | --- |
| Authentication | `login`, `logout`, `get_user` |
| Flights | `add_flight`, `edit_flight`, `delete_flight`, `join_tow_flights`, `get_flight`, `list_flights_today`, `list_flights_by_date`, `list_flights_by_plane`, `list_my_flights`, `list_flights_by_user`, `list_modified_flights`, `list_flights_in_daterange` |
| Calendar | `list_public_calendar`, `list_my_calendar`, `list_appointments`, `add_appointment`, `edit_appointment`, `delete_appointment` |
| Members | `list_users` |
| Reservations | `list_active_reservations` |
| Maintenance | `get_airplane_maintenance` |
| Accounting | `add_booking`, `edit_booking`, `get_booking`, `list_bookings_today`, `list_bookings_year`, `list_bookings_in_daterange` |
| Work hours | `list_workhours`, `add_workhours`, `list_workhour_categories` |
| Sales | `list_articles`, `list_sales_in_daterange`, `list_modified_sales`, `list_sales_by_date`, `list_sales_today`, `add_sale` |
| Backup | `get_backup_archive` |
| Vouchers | `list_vouchers`, `add_voucher` |

## TOTP helper

The TOTP implementation is exported for direct use, for example to verify that
a configured secret matches what an authenticator app shows:

```python
from vereinsflieger import generate_totp, make_totp_provider

code = generate_totp("JBSWY3DPEHPK3PXP")          # current 6-digit code
provider = make_totp_provider("JBSWY3DPEHPK3PXP")  # for Client(two_factor_provider=...)
```

The decoder accepts mixed case, embedded whitespace, hyphens, and missing
base32 padding.

## Error handling

All errors derive from `VereinsfliegerError`:

- `AuthenticationException` — wrong credentials, expired session, 401/403.
- `TwoFactorRequiredException` — the API signalled `need_2fa` but no provider
  is configured.
- `APIException` — transport errors, 400/404, and non-JSON responses.

## Rate limits and terms of use

The Vereinsflieger API limits each `appkey` to 500 requests per day. Per the
provider's documentation, commercial use of the interface is not permitted.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT — see [LICENSE](LICENSE).
