# Ephemeris Core — Wiki

A cryptographic authentication **prototype** that mixes planetary distance into a
SHA-512 challenge, bound to a device ("Ghost Seal") and shifted in time by a PIN.
It now includes a trusted-device model with an **8-digit device code** for
authorizing new devices and a **recovery phrase** for regaining access.

> ⚠️ Prototype only. Not for production. TLS is assumed in any real deployment.

## Pages
- **[[Architecture]]** — components, data flow, database schema.
- **[[Authentication Flow]]** — first device, new device, and recovery flows + the hash formula.
- **[[API Reference]]** — every `login.php` action with request/response shapes.
- **[[Security Model]]** — what is actually secret, entropy budget, hardening, and known limitations.
- **[[Setup]]** — how to run it locally.

## At a glance
| Concern | Mechanism |
|---|---|
| Everyday login | password + planet + PIN + device seal |
| Add a new device | password **+** 8-digit device code |
| Lost everything | 6-word recovery phrase |
| Replay | ±120s timestamp window + single-use login hashes |
| Brute force | per-username/IP rate limiting (login / device-code / recovery) |
| Secret storage | device code & recovery phrase stored as **argon2** hashes |

## Known limitation
The account password is still stored in plaintext (inherent to the current
challenge scheme). The unused SRP/PAKE code under `server-php/`,
`server-csharp/`, and `client-js/` is the intended fix and the recommended next
step. See **[[Security Model]]**.
