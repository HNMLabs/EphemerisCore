# Architecture

## Components

| Layer | Files | Role |
|---|---|---|
| Login UI | `index.html` | Login + inline new-device authorization (8-digit code). |
| Register | `register.html` | Create an account (username + password). |
| First enrollment | `welcome.html` | Enroll the first device; shows the one-time device code + recovery phrase. |
| Recovery | `recover.html` | Reset device access with the recovery phrase. |
| Panel | `panel.html` | Post-login landing; validates the session server-side. |
| API | `login.php` | Single JSON endpoint (SQLite). All actions live here. |
| Setup | `setup.php` | Creates the SQLite DB and seeds demo users. |
| Words | `wordlist.php` | 285-word list used to generate recovery phrases. |
| Debug | `diag.php`, `fix_seal.php` | Localhost-only inspection / manual seal insert. |
| Unused (intended fix) | `server-php/`, `server-csharp/`, `client-js/` | SRP/PAKE implementation. |

## Database schema (SQLite, `auth.db`)

```
users          (id, username UNIQUE, password, seal[legacy],
                device_code_hash, recovery_hash, created_at)
device_seals   (id, username, seal, label, created_at)        -- one row per device
sessions       (id, username, token, created_at)
used_hashes    (hash PRIMARY KEY, created_at)                  -- replay protection
login_attempts (id, username, ip, kind, created_at)           -- kind: login|device_code|recovery
```

- `users.seal` is a legacy single-seal column; on startup `login.php` migrates any
  non-empty value into `device_seals` and stops using it.
- `device_code_hash` and `recovery_hash` hold **argon2** hashes only.

## Request flow (everyday login)

1. Client computes `distance` for the chosen planet at `T' = now − PIN×60`.
2. Client sends `{ username, planet, pin, ts, hash }` where
   `hash = SHA-512(password + distance.toFixed(3) + seal)`.
3. Server recomputes the distance over a ±2s window and compares the hash
   against each of the user's enrolled seals (and the password-only form).
4. On success it records the hash as used (replay), clears failed attempts,
   and issues a session token.

See **[[Authentication Flow]]** for the new-device and recovery branches.

## Security tunables (`login.php`)

| Constant | Value | Meaning |
|---|---|---|
| `TS_WINDOW` | 120s | Allowed clock skew between client `ts` and server. |
| `REPLAY_TTL` | 600s | How long a used login hash is remembered. |
| `SESSION_TTL` | 86400s | Session token lifetime. |
| `MAX_FAILS` / `FAIL_WINDOW` | 10 / 300s | Login throttle. |
| `MAX_CODE_FAILS` / `CODE_WINDOW` | 5 / 900s | Device-code throttle. |
| `MAX_REC_FAILS` / `REC_WINDOW` | 5 / 3600s | Recovery throttle. |
