# Authentication Flow

## Hash formula

```
hash = SHA-512( password + distance.toFixed(3) + seal )

shifted time:  T' = ts − (PIN × 60)   seconds
distance       = planetDistanceKm(planet, T')
```

When proving **only the password** (first login, or new-device authorization),
the seal is omitted:

```
hash = SHA-512( password + distance.toFixed(3) )
```

The server tries the timestamp ±2 seconds to absorb JS/PHP float-rounding at the
3rd decimal, and matches against **every** enrolled seal for the user.

---

## 1) First device (bootstrap)

```
register ─▶ login (password + planet + PIN, no seal)
         ─▶ server: 0 seals + password matches  ⇒ ok, needsEnroll=true
         ─▶ welcome.html: client generates a 256-bit seal, calls enroll_device
         ─▶ server stores the seal, generates an 8-digit device code
            and a 6-word recovery phrase, returns them ONCE
         ─▶ user saves the code + phrase, continues to panel
```

The device code and recovery phrase are shown **only once**; only their argon2
hashes are persisted.

## 2) New / additional device

```
login (password + planet + PIN, no matching seal)
   ─▶ server: password matches but no seal  ⇒ 403 { needsDeviceAuth: true }
   ─▶ index.html reveals the "Device Code" field
   ─▶ user enters the 8-digit code; client generates a new seal and
      recomputes a fresh password-only hash
   ─▶ authorize_device: server verifies password + code, stores the new seal,
      issues a session
```

Both factors are required: a correct password **and** the 8-digit code. Each is
rate-limited independently.

## 3) Recovery

```
recover.html: username + recovery phrase (+ optional new password)
   ─▶ recover: server verifies the phrase (argon2, normalized, rate-limited)
   ─▶ deletes all device_seals + sessions, optionally updates the password,
      clears the old code/recovery, issues a session, needsEnroll=true
   ─▶ welcome.html: user enrolls a fresh first device ⇒ a NEW code + phrase
```

Recovery is the account's last resort, so it is the most heavily throttled path
and its strength caps overall account security — hence the phrase is **system-
generated** (real entropy), matched **exactly** (after lowercase/whitespace
normalization), never partially.

## State the server distinguishes

| Condition | Result |
|---|---|
| Password matches a seal | Full login |
| Password matches, user has **0** seals | `needsEnroll` (bootstrap first device) |
| Password matches, seals exist, none match this device | `needsDeviceAuth` |
| Password does not match | Generic `403 Login failed` |
