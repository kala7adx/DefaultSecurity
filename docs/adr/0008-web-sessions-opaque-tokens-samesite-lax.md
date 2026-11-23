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
  - Login has its own pre-session CSRF token plus the `Origin` check, against login CSRF.
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
  - Throttling: per account and per IP, stored in Postgres so it works across replicas.
    Thresholds are configurable; the default allows at most 10 attempts per 5 minutes per account,
    in line with Cyber Essentials v3.3's guidance. Responses are `429` with `Retry-After`, and
    failures are audit-logged.
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
