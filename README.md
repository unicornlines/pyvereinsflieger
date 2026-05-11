# vereinsflieger

A Python REST client for the [Vereinsflieger](https://www.vereinsflieger.de)
flight logbook service. Implements every endpoint of the published
`REST-API-Spezifikation` (version 2025-07-29), with transparent two-factor
authentication via stored TOTP secrets.

## Features

- Full coverage of all documented endpoints: authentication, flights,
  calendar, members, reservations, maintenance, accounting bookings, work
  hours, sales, backup, vouchers.
- Built-in TOTP code generation (RFC 6238) — pass a `totp_secret` once and
  let the client handle 2FA automatically.
- Typed, fully docstringed, modern Python (3.12+, PEP 695 type aliases,
  `match`/`case`, `Self`).
- Context-manager API that logs out and closes the HTTP session on exit.
- Sensible defaults: password is MD5-hashed locally before transmission;
  credentials never end up in URL query strings; per-request timeouts.

## Install

```bash
pip install git+https://github.com/<you>/vereinsflieger.git@v0.1.0
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

If your account does not use 2FA, omit `totp_secret`:

```python
with Client(appkey="YOUR_APP_KEY") as vf:
    vf.login(username="alice", password="hunter2")
    ...
```

For interactive use (prompts on stdin) or for sourcing the code from a UI,
pass a callable to `two_factor_provider` instead of `totp_secret`.

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

The TOTP implementation is exported for direct use, e.g. for verifying that a
configured secret matches what an authenticator app shows:

```python
from vereinsflieger import generate_totp, make_totp_provider

code = generate_totp("JBSWY3DPEHPK3PXP")  # current 6-digit code
provider = make_totp_provider("JBSWY3DPEHPK3PXP")  # for Client(two_factor_provider=...)
```

The decoder accepts mixed case, embedded whitespace, hyphens, and missing
base32 padding.

## Exceptions

All errors derive from `VereinsfliegerError`:

- `AuthenticationException` — wrong credentials, expired session, 401/403.
- `TwoFactorRequiredException` — API signalled `need_2fa` but no provider
  is configured.
- `APIException` — transport errors, 400/404, non-JSON responses.

## Rate limit

The Vereinsflieger API limits each `appkey` to 500 requests per day.
Commercial use of the interface is not permitted by the provider.

## License

MIT — see [LICENSE](LICENSE).
