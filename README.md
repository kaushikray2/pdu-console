# PDU Console

A modern web console for **APC Switched Rack PDUs** that expose the classic NMC
web UI. It replaces the dated built-in pages with a fast, phone-friendly
dashboard — live loads and outlet states, one-click control, outlet groups and
locks — while each PDU itself stays the source of truth. One console manages any number of PDUs: the landing page is an overview of all of them, and each PDU has its own detail page and its own settings — connections, groups, locks and poll intervals are never shared or mixed between PDUs.

Python standard library only; runs as a single small Docker container.

## Features
- Live status: per-bank and total load, per-outlet state, alarm badge;
  background polling at a configurable interval (5–300 s).
- **Control:** every outlet can be switched (On / Reboot / Off) after a
  confirmation prompt.
- **Groups:** named groups of outlets appear as one card and switch together
  with a single button. An outlet can belong to only one group; a grouped
  outlet's own card greys out and its controls are disabled — it is operated
  from the group card.
- **Locks:** any outlet or group can be locked. Switching a locked target —
  and unlocking it — requires the console password; locked targets show
  greyed-out buttons.
- **Outlet names** are edited in Settings and written to the PDU itself
  (the NMC caps names at 23 characters). A rename re-submits the outlet's
  config form with every other setting (power delays, reboot duration)
  preserved unchanged.
- **Settings page:** PDU connection (IP/hostname, display name, username,
  password) with verify-then-save — candidate settings must pass a live
  connection test before anything is stored, so a typo cannot lock the
  console out of the PDU; refresh interval; blocked-address list; console
  password change; recent-activity (audit) viewer.
- Console-password auth (pbkdf2, 12 h sessions, login throttling), the PDU
  credential encrypted at rest, and a full audit log of every action.

Nothing site-specific is baked into the code: the PDU address, credentials,
display name, poll interval and blocked list are all runtime settings stored
in the `data/` directory.

## Quick start
```sh
docker compose up -d --build
```
The console listens on port **8092** by default (set `PDU_CONSOLE_PORT` to
change it). Open it in a browser:

1. Create the console password on the first-run screen.
2. Use **+ Add PDU**, enter the PDU IP, a display name, and its username and password (the connection is tested before anything is saved).
3. The overview starts polling it immediately. Add more PDUs the same way; open any PDU card for its outlets, groups and settings.

## Safety model
- The console only ever contacts the single PDU it is configured for.
- The **blocked list** (Settings) holds addresses the console must never
  connect to — e.g. a production PDU sharing the management network. Blocked
  addresses are refused even if entered as the connection target.
- Locks are a console-level guard (they stop accidents in this UI; anyone
  with the PDU's own credentials can still use its native pages).
- Run it on a trusted LAN only; it serves plain HTTP on the host port.

## Data files (`data/` volume)
- `auth.json` — console password hash; `.key` — the encryption key for the stored PDU credentials.
- `settings.json` — console-wide settings (the blocked list).
- `pdus/<id>/` — one folder per managed PDU: `device.json` (its connection, credential encrypted at rest), `groups.json`, `locks.json`, `settings.json` (its poll interval). Nothing is shared between these folders.
- `pdus-removed/` — archives of removed PDUs.
- `audit.log` — every sign-in, control, group, lock, rename and settings event.
- Upgrading from the single-PDU layout: the old root-level `device.json`, `groups.json` and `locks.json` are migrated into `pdus/<id>/` automatically on first start.

## How control works (NMC classic UI)
Form login on `/logon.htm`, status parsed from the home page and
`/olstatus.htm`, control via `/outlctrl.htm` (POST `/Forms/outlctrl1` →
confirmation form → Apply), renames via `/olnamcfg.htm?outlet=N`
(POST `/Forms/olnamcfg1`). Outlet counts and bank layouts are read from the
PDU, so 16/24/32-outlet units all work.

## Tests
`tests/` holds a fake NMC (a stand-in for the card's web UI) and an
integration suite that runs the real server against it — auth, add/remove,
control with state verification, groups, locks, renames, per-PDU isolation,
blocked list, session reuse/expiry, 403 backoff, and legacy-data migration.
No real PDU is touched:

```sh
python3 tests/run_tests.py
```

---

Developed by [SiliconBrane Inc.](https://siliconbrane.com)

Version **v0.01**
