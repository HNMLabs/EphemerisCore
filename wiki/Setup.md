# Setup

## Requirements
- PHP 8.x with `pdo_sqlite` (argon2id recommended; bcrypt is the fallback).
- No external services — the store is a local SQLite file (`auth.db`).

## Run locally

```bash
# from the project root
php setup.php                 # creates auth.db + seeds demo users
php -S 127.0.0.1:8765         # serve the app
```

Then open <http://127.0.0.1:8765/index.html>.

Seed users (created by `setup.php`):

| Username | Password |
|---|---|
| `kullanici` | `sifre123` |
| `admin` | `admin123` |

> `auth.db` is gitignored. Delete it to start clean, then re-run `setup.php`.

## Try the flows

1. **First device** — register a user, log in (pick a planet + 4-digit PIN). On
   `welcome.html`, **save the 8-digit device code and the 6-word recovery
   phrase** (shown once), then continue.
2. **Same device** — log out and back in: no code is needed.
3. **New device** — open a **private/incognito window**, log in with the same
   credentials → "New device detected" → enter the 8-digit code to authorize it.
4. **Recovery** — "Recover access" → username + recovery phrase → you are taken
   back to enrollment and issued a fresh code + phrase.

## Debug tools (localhost only)

```bash
curl "http://127.0.0.1:8765/diag.php?u=alice"
# username / enrolled_devices / device_code(SET|UNSET) / recovery_phrase(SET|UNSET)

curl "http://127.0.0.1:8765/fix_seal.php?u=alice&seal=<64 hex>"
# manually inserts a device seal (debugging)
```

## Notes
- The client and server share identical planet parameters and the J2000 epoch so
  both compute the same distance; only the SHA-512 hash crosses the wire.
- See **[[Authentication Flow]]** and **[[API Reference]]** for details.
