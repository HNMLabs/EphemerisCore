# Security Model

## What is actually secret?

The strength of a "client computes `H(secrets…)`, server checks" scheme equals
the entropy of the values that are **not transmitted** and **not guessable**.

| Value | Transmitted? | Real entropy | Role |
|---|---|---|---|
| Password | No (only inside the hash) | depends on user | Primary secret. **Stored plaintext** today (limitation). |
| Device seal | Once, at enrollment | 256-bit (random) | "Something you have" — binds login to a device. |
| Planet | **Yes** (cleartext) | ~2 bits | Decorative / everyday factor — adds no secrecy in transit. |
| PIN | **Yes** (cleartext) | ~13 bits | Decorative / everyday factor — adds no secrecy in transit. |
| Device code | No | ~27 bits (random 8 digits) | Gate for authorizing a new device. argon2 + lockout. |
| Recovery phrase | No | ~49 bits (6 of 285 words) | Account last-resort. argon2 + heavy lockout. |

### Key truth about "planetary distance"
`distance` is a **deterministic function** of `(planet, time, PIN)`, not entropy.
Because the planet and PIN are sent in cleartext, an eavesdropper can recompute
the distance and the scheme reduces to *password + device seal*. The cosmic
layer is a UX theme, not cryptographic strength — treat the planet/PIN as a
memorable, weak **secondary** factor only.

### Entropy comes from randomness, not formatting
The 8-digit device code and the recovery phrase carry real strength only because
they are **server-generated with a CSPRNG**. A code "derived" from the planet+PIN
would inherit their ~15 bits regardless of how long it looks.

## Hardening implemented

- **Replay protection:** client `ts` must be within ±120s of the server, and
  each redeemed login hash is single-use (`used_hashes`).
- **Rate limiting / lockout:** separate counters for login (10/5min),
  device-code (5/15min), and recovery (5/60min), per username+IP.
- **Session TTL:** tokens expire after 24h; `verify_session` enforces it and
  `panel.html` checks on load.
- **Secret storage:** device code and recovery phrase stored as **argon2id**
  hashes (falls back to bcrypt if argon2 is unavailable).
- **No user enumeration:** login failures return a generic `403`.
- **Debug tools** (`diag.php`, `fix_seal.php`) are restricted to localhost.
- **Defense in depth:** adding a device needs the password **and** the code.

## Threats & current posture

| Threat | Posture |
|---|---|
| Eavesdropper replays a captured login | Blocked (timestamp window + single-use hash). |
| Online password brute force | Throttled + lockout. |
| Attacker knows password, no device | Cannot log in; needs the 8-digit code to add a device. |
| Stolen device code attempts | argon2 + 5-attempt lockout. |
| **Database leak** | ⚠️ Reveals plaintext passwords. Device code / recovery are argon2 (but low-entropy code is brute-forceable offline given enough time). |

## Known limitation & next step

The server must recompute the client's hash, so it stores the **plaintext
password**. This is inherent to the challenge scheme, not a bug. The intended
fix is to migrate login to the **SRP/PAKE** implementation already present in the
repo (`server-php/SrpServer.php`, `server-csharp/SrpServer.cs`,
`client-js/srp_client.js`), after which the server keeps only a verifier and no
plaintext password ever exists.

> Prototype only. TLS is mandatory for any real deployment.
