# Ephemeris Core
A cryptographic authentication prototype utilizing planetary distance + SHA-512 with a Ghost Seal (device binding) and Time-Shift PIN.

## Pages
- `index.html` Login (+ new-device authorization)
- `register.html` Register
- `welcome.html` First-device enrollment (shows the one-time device code + recovery phrase)
- `panel.html` User panel
- `recover.html` Recover access with the recovery phrase

## Backend
- `login.php` API (SQLite). Actions: `register_user`, login, `enroll_device`, `authorize_device`, `recover`, `verify_session`.
- `setup.php` Create the SQLite DB and seed demo users.
- `wordlist.php` Word list used to generate recovery phrases.
- `diag.php`, `fix_seal.php` Localhost-only debug tools.

## Device model
- Everyday login on an enrolled device: password + planet + PIN + device seal.
- The **first device** bootstraps the account and is issued an **8-digit device code** and a **6-word recovery phrase**, shown once.
- **Adding another device** requires the password *and* the 8-digit device code.
- **Recovery phrase** resets device access (and optionally the password) if everything is lost.

## Security notes
- Prototype only. Do not use in production.
- TLS is mandatory for any real deployment.
- Replay protection (timestamp window + used-hash table), per-username/IP rate limiting, and session TTL are enforced in `login.php`.
- The 8-digit code and recovery phrase are stored only as argon2 hashes.
- **Known limitation:** the account password is still stored in plaintext (inherent to the current challenge scheme). The unused SRP/PAKE code under `server-php/`, `server-csharp/`, `client-js/` is the intended fix.
