# Threat model

## Assets and actors

Protect account credentials, sessions, private ticket content, role assignments, audit integrity, and service availability. Actors include unauthenticated visitors, malicious students, compromised support accounts, administrators and infrastructure operators.

## Trust boundaries

```text
Untrusted browser
    | HTTPS, same-origin requests
Netlify static hosting + Functions
    | server-only credentials / verified TLS
Managed PostgreSQL

Functions --> optional team-controlled HTTPS alert receiver
```

The browser cannot be trusted to enforce ownership, roles or input constraints. Functions check those controls. PostgreSQL persists session state and rate counters across function instances. Hosting infrastructure must mitigate network-level traffic floods. The alert destination is trusted operator configuration, never user input.

## Principal abuse cases

1. A student substitutes another ticket's UUID: ownership/assignment filtering returns 404.
2. A visitor submits SQL syntax: query parameters preserve it as data.
3. A user saves an HTML payload: the frontend displays literal text and CSP adds a second layer.
4. An external page submits a change: origin, JSON/custom-header checks, CSRF tokens and cookies reject it.
5. A stolen expired or logged-out cookie is reused: server-side expiry/deletion rejects it.
6. A user adds `role=admin` to registration: explicit field allowlists reject it.
7. A bot guesses passwords or creates many tickets: shared limits constrain individual sources/accounts; alerts record repeated failures.
8. The database or log write fails: sensitive transactions roll back and clients receive generic errors.
9. A distributed flood exceeds application limits: infrastructure controls and operational response are required; the application makes no guarantee.

## Assumptions

Deployment credentials, database owners, administrators and CI maintainers are trusted. Runtime database privileges must be restricted separately from migrations. PostgreSQL and Netlify configuration are part of the security boundary. Preview deployments must not expose production data. Secrets never belong in frontend code or Git history.
