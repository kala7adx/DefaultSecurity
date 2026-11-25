# 0008. Web sessions: opaque server-side tokens, SameSite=Lax + CSRF token

- Status: Accepted (owner decision 2026-11-23)
- Date: 2026-11-23
- Deciders: Owner, Claude Code

## Context
The kickoff asked for "JWT session auth". `SECURE_CODING.md` targets ASVS 5.0 Level 2, which
requires that logout and password change actually terminate sessions, and that sessions have
idle and absolute timeouts. Stateless JWTs can't be revoked without a server-side denylist,
which brings back state anyway. The owner also requires that **links in Slack, Teams and Jira
notifications open logged-in**. Those are cross-site top-level navigations, which
`SameSite=Strict` cookies don't accompany.

## Decision
- **Opaque sessions:**
  - A 256-bit CSPRNG token in cookie `__Host-skyline_session`: `HttpOnly; Secure; SameSite=Lax;
    Path=/`, no `Domain`.
  - Only the SHA-256 of the token is stored, in `sessions`, and resolved through a
    `SECURITY DEFINER` function.
  - Idle timeout 30 minutes, absolute 12 hours, both configurable.
  - A new session is issued at login (no fixation). Logout (POST) revokes it, and a password
    change revokes all of the user's sessions.
- **CSRF under Lax:**
  - **GET/HEAD/OPTIONS never change state.** A route-enumeration test fails if any state-changing
    handler is reachable by a safe method.
  - Double-submit token: cookie `__Host-skyline_csrf` (`Secure; SameSite=Lax`, readable by
    same-origin JS) must equal the `X-CSRF-Token` header on unsafe methods. The token is
    `HMAC(server_key, session_id)`, so it can't be planted or reused across sessions.
  - Unsafe methods also need an `Origin` header matching the configured public origin, and
    requests with `Sec-Fetch-Site: cross-site` are rejected.
  - Login CSRF (amended 2026-11-24 after the Phase 0 API review): there is no pre-session
    token. Login is blocked cross-site by the `Origin` check, the `Sec-Fetch-Site` check and a
    JSON-only body (a cross-site form can only send `text/plain`, `urlencoded` or `multipart`,
    which return 422). Revisit if login ever accepts form posts or an SSO callback.
- **Deep links:** unauthenticated requests go to `/login?next=<path>`. `next` must be a
  same-origin relative path: it must start with a single `/`, not `//` or `/\`, contain no scheme
  or control characters, and is checked again after URL-decoding. Anything else becomes `/`.
  Open-redirect tests cover the encoded variants.
- **Passwords and login:**
  - Hashing: argon2id (argon2-cffi defaults).
  - Policy: at least 12 characters with a 1,024-character cap, a common-password blocklist, and
    a forced change for the bootstrap admin. The cap exists only to bound hashing input. It is
    far above ASVS's "allow at least 64" and effectively unrestricted, as Cyber Essentials v3.3
    asks.
  - Enumeration resistance: when the user doesn't exist, verify against a dummy hash so timing
    reveals nothing.
  - Throttling, not lockout (amended 2026-11-25): Cyber Essentials v3.3 (User Access Control,
    password-based authentication, p. 21) accepts "at least one of" MFA, throttling where "the
    length of time the user must wait between attempts increases with each unsuccessful
    attempt" with no more than 10 guesses in 5 minutes, or locking after 10 failures. Skyline
    uses throttling, stored in Postgres so it works across replicas:
    - **Accounts:** after each consecutive failure the next attempt waits twice as long (1 s,
      2 s, 4 s … 256 s). From the 10th failure, each wait is a 5-minute temporary lock that ends
      on its own. Refused attempts are never recorded, so hammering can't extend a lock. A
      success, or 60 minutes with no failure, ends the streak. An attacker guessing as fast as
      allowed gets 9 guesses in the first 5 minutes and then one per lock: never more than 10 in
      any 5 minutes, and about 12 an hour sustained (bursting and pausing gets fewer).
    - **Hard ceilings:** at most 10 failures per 5 minutes per throttling subject, counted
      whether or not the real user signs in between (a success ends the wait streak, so
      without this an attacker could guess again straight after each of the user's sign-ins),
      and 100 per IP bucket. The settings can't be set looser than Cyber Essentials allows.
    - **Known devices (OWASP device cookies):** a successful password check sets
      `__Host-skyline_device` (HttpOnly, Secure, SameSite=Strict, 90 days): an HMAC over the
      account's subject, a fingerprint of its current password hash, the issue time and a
      random nonce. A browser presenting a valid cookie for the account it's signing in to is
      throttled on its own subject (same waits and ceiling) instead of the account's. So an
      attacker who keeps the account locked (one request per lock, about 12 an hour) can't keep
      the real user's own browsers out, and a signed-in user can still change their password.
    - Forged, expired or other-account cookies fall back to the account, and so does every
      cookie issued before the last password change. Cookies collected by someone who once knew
      the password are worthless once it changes. Each valid cookie is an extra budget of 10
      guesses per 5 minutes, so a stolen cookie gives a second budget until the next password
      change. Rotating the session key revokes every device cookie at once. A browser without
      a cookie (new, or cookies cleared) is still held by the account's lock: residual risk R9.
      Audit rows record whose budget an attempt used (`via`: account or device).
    - **Concurrency:** each reservation starts the next wait at once, so guesses are spaced by
      the wait however many requests arrive in parallel (several can still be hashing at once).
    - All values are configurable (`SKYLINE_LOGIN_*`). Responses are `429` with `Retry-After`
      and a message giving the wait, identical for unknown emails. Failures and refusals are
      audit-logged.
    - Source: https://www.ncsc.gov.uk/files/cyber-essentials-requirements-for-it-infrastructure-v3-3.pdf
- **Topology:** the browser talks only to the web origin, and `/api/*` is routed to the API by a
  Next.js rewrite locally or an ALB/Ingress path rule in production. No CORS.
- **JWTs are reserved** for future API and service tokens and for validating OIDC ID tokens
  (Phase 9), with pinned `alg`, `iss`/`aud` checks and rotated keys.

## Consequences
- Sessions can be revoked immediately. Session lookup costs one indexed query per request, which
  is negligible.
- Lax means a cross-site GET carries the session, so the "safe methods are side-effect free" rule
  becomes a tested invariant rather than a convention.
- Browsers accept `Secure` cookies on `http://localhost` (Chromium, Firefox). Local Compose works
  without TLS, and every other deployment terminates TLS.

## Alternatives considered
- Stateless JWTs in cookies: not revocable without a denylist (rejected for ASVS L2).
- Short JWT + refresh token: meets the requirements but has more moving parts for no benefit to a
  first-party UI.
- `SameSite=Strict`: stronger CSRF posture, but breaks the notification deep-link requirement.

## References
- OWASP ASVS 5.0: https://owasp.org/www-project-application-security-verification-standard/
- OWASP CSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- Cookie prefixes (`__Host-`): https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#cookie_prefixes
- NCSC Cyber Essentials v3.3 requirements: https://www.ncsc.gov.uk/cyberessentials/resources
