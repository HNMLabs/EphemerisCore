# API Reference

All requests are `POST application/json` to `login.php`. All responses are JSON
with at least `{ "ok": bool }`. Usernames are case-insensitive. Errors use
HTTP status codes (`400` bad input, `401` invalid session, `403` auth failure,
`409` conflict, `429` rate-limited, `500` server).

---

### `register_user`
```json
{ "action": "register_user", "username": "alice", "password": "secret" }
```
- **200** `{ "ok": true, "message": "Registration successful. Please login." }`
- **409** `{ "ok": false, "message": "User already exists." }`

---

### Login (no `action`)
```json
{ "username": "alice", "planet": "mars", "pin": "0007", "ts": 1700000000, "hash": "<128 hex>" }
```
- **200** `{ "ok": true, "message": "...", "token": "<hex>", "needsEnroll": false }`
- **403** `{ "ok": false, "needsDeviceAuth": true, "message": "New device detected..." }` — correct password, unrecognized device.
- **403** `{ "ok": false, "message": "Login failed" }`
- **429** `{ "ok": false, "message": "Too many attempts. Try again later." }`

`hash = SHA-512(password + distance.toFixed(3) + seal)`; omit the seal for a
password-only proof. `ts` must be within ±120s of server time.

---

### `enroll_device` (first device only)
```json
{ "action": "enroll_device", "username": "alice", "token": "<session>", "seal": "<64 hex>" }
```
Requires a valid session and that the user has **no** enrolled devices yet.
- **200** `{ "ok": true, "message": "Device sealed.", "deviceCode": "01234567", "recoveryPhrase": "fox river ... oak" }` — **shown once**.
- **409** `{ "ok": false, "message": "Account already set up. Use your device code to add this device." }`

---

### `authorize_device` (add a subsequent device)
```json
{ "action": "authorize_device", "username": "alice", "planet": "mars",
  "pin": "0007", "ts": 1700000000, "hash": "<password-only 128 hex>",
  "code": "01234567", "seal": "<new 64 hex>" }
```
Verifies the password (password-only hash) **and** the 8-digit code.
- **200** `{ "ok": true, "message": "Device authorized.", "token": "<hex>", "needsEnroll": false }`
- **403** `{ "ok": false, "message": "Invalid device code." }` (or "Authorization failed.")
- **429** rate-limited (5 wrong codes / 15 min).

---

### `recover`
```json
{ "action": "recover", "username": "alice",
  "recovery": "fox river ... oak", "newPassword": "" }
```
Resets device access; optionally sets a new password if `newPassword` is non-empty.
- **200** `{ "ok": true, "message": "Recovery successful. Enroll this device.", "token": "<hex>", "needsEnroll": true }`
- **403** `{ "ok": false, "message": "Recovery failed." }`
- **429** rate-limited (5 wrong attempts / 60 min).

The phrase is normalized (lowercased, whitespace collapsed) and matched exactly.

---

### `verify_session`
```json
{ "action": "verify_session", "username": "alice", "token": "<session>" }
```
- **200** `{ "ok": true }`
- **401** `{ "ok": false, "message": "Invalid or expired session." }`

---

## Planets
`mars`, `venus`, `jupiter`, `saturn`. Each has fixed orbital parameters
(`a`, `e`, `period`, `phase`) shared by client and server so both compute the
same distance.
