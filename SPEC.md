# Ephemeris Core - Protocol Spec

This document describes the prototype logic for planetary distance based authentication with Ghost Seal, Time-Shift PIN, device authorization, and recovery.

## Core Flow
1. Register user (username, password).
2. Login with password + planet + PIN.
3. First login (no seal) bootstraps the account:
   - Enroll the device (Ghost Seal).
   - Server issues an 8-digit device code and a 6-word recovery phrase (shown once).
4. Subsequent logins on an enrolled device require the Ghost Seal.
5. Logging in from a new device requires the password + the 8-digit device code.
6. Losing access is resolved with the recovery phrase.

## Hash Formula
SHA-512( Password + Distance_At_Shifted_Time + Ghost_Seal )

When proving only the password (first login, or new-device authorization), the
seal is omitted: SHA-512( Password + Distance_At_Shifted_Time ).

Shifted time:
T' = T - (PIN * 60 seconds)

The server matches against each of the user's enrolled seals; if only the
password-only form matches it means the device is unrecognized.

## Secrets & storage
- Password: stored as-is (prototype limitation; see SRP migration note).
- Device seals: one row per enrolled device (`device_seals`).
- Device code (8 digits) and recovery phrase (6 random words): argon2 hashes only.

## Hardening
- Client timestamp must be within ±120s of server time.
- Each redeemed login hash is single-use (replay protection).
- Rate limiting: login, device-code, and recovery attempts each have their own
  lockout thresholds.
- Sessions expire after 24h; `verify_session` validates them.

## Notes
- Prototype only. Not for production.
- TLS is required in real deployments.
- The 8-digit device code is the last gate against a password-knowing attacker
  who lacks an enrolled device; argon2 + lockout protect it.
