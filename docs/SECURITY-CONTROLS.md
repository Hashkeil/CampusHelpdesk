# Security controls and evidence

Mappings describe relevant weaknesses, not blanket CWE compliance. Review the implementation and rerun the tests after every change.

| Threat / CWE | Implemented controls | Evidence / limitations |
| --- | --- | --- |
| SQL injection / CWE-89 | Parameterized `pg` queries; SQL identifiers are fixed in source | Integration payload tests; use a least-privilege runtime DB role |
| XSS / CWE-79 | User text rendered through `textContent`; plain-text tickets; restrictive CSP; no inline scripts | Review `public/app.js`; browser execution and deployed CSP need verification |
| CSRF / CWE-352 | Exact origin checks, custom request header, JSON-only writes, session-bound random CSRF token, SameSite=Strict | Tests reject incorrect origins and tokens; login/register use origin/header checks before authentication |
| Authorization / CWE-862, CWE-639 | Server-side student ownership and staff-assignment checks; admin-only management | Cross-account read/reply and staff tests; no client-provided role accepted at registration |
| Password storage / CWE-916 | Random salts; scrypt N=32768, r=8, p=3; constant-time verification | Password tests; 15–128 character policy; no MFA or compromised-password service yet |
| Session management / CWE-384, CWE-613 | Random 256-bit opaque tokens; only token hashes stored; 8-hour expiry; one session per user; revocation on logout/block/role update | Session rotation, expiry and revocation tests; fixed absolute lifetime |
| Cookies / CWE-614, CWE-1004 | Production Secure, HttpOnly, SameSite=Strict, Path=/, no Domain, __Host prefix | Cookie unit tests; inspect production browser cookies after deployment |
| Input validation / CWE-20 | Allowed fields, lengths, enums, UUIDs, request sizes; DB constraints | Unknown privilege fields and invalid data rejected; validation is not the SQL/XSS defense |
| Resource exhaustion / CWE-400, CWE-770 | Shared atomic DB rate counters on every request class (global reads, authentication, failed logins, ticket creation, replies, status updates); expired counters and sessions purged automatically; bounded bodies, lists, queries and connection pool | API tests for 429 and 413; counters are not an edge DDoS shield |
| Logging / CWE-778 | Structured audit table; sensitive mutations and logs share a transaction; generic client errors and correlation IDs | No passwords, cookies, ticket text or email addresses in audit records; account IDs can still be personal data |
| Alerting | Fifth failed login per source/15 minutes creates one alert; HTTPS webhook with timeout, redirects disabled, recorded result | Unconfigured alerts visible in admin UI; delivery not assumed; no durable retries yet |
| Information exposure / CWE-209 | Generic login errors; generic duplicate-registration response; generic server failure details | Functional tests; this is not a guarantee of indistinguishable timing |
| Configuration / CWE-798 | Environment secrets, git ignore rules, externalized DB connection, production HTTPS requirement | Operator must provision secrets and database permissions correctly |

## Allowlist and blocklist

Allowlists enforce allowed roles, priorities, categories, statuses, request properties, methods, and the origin. Account blocking is the explicit deny mechanism; it revokes sessions. SQL keywords and HTML strings are deliberately not blacklisted: legitimate text is preserved, parameterized, and rendered safely.

## Abuse controls

- General API: 120 requests per source per minute.
- Reading (every GET endpoint): 120 per account per minute.
- Authentication: 20 attempts per source per 15 minutes; 10 failed attempts per normalized email per 15 minutes (successful sign-ins never count against the email limit, so attacks cannot blacklist a known user).
- Ticket status/assignment updates: 30 per account per minute.
- Ticket creation: 20 per account per hour.
- Replies: 60 per account per hour.
- API body: 16 KiB; ticket text: 4,000 characters; reply: 2,000.
- Lists: 20 tickets/page, offset capped at 10,000; latest 100 replies, users or audit events; latest 50 alerts.
- PostgreSQL statement and connection timeouts: 5 seconds; pool capped per function instance.

Source addresses are HMAC-pseudonymized before rate-counter storage. Only Netlify's platform-supplied client-IP header is used in production; local development shares one bucket. Verify this trust boundary on the deployed platform. NAT users may share a limit; botnets may use many sources. No in-app limiter stops traffic before it reaches hosting infrastructure or guarantees cost bounds.

## Operations and retention

Housekeeping is automated: expired `rate_limits` counters and `sessions` that expired more than one day ago are deleted opportunistically (at most once per minute per function instance) while serving traffic. Agree a retention period for `audit_events` and `security_alerts` (for example 30 days for the lab) and enforce it operationally. Monitor database availability, capacity, alert failures and hosting usage. Limit audit access and do not place real secrets in tickets.

Webhook delivery is best effort, synchronous and deduplicated per threshold window. A failed delivery remains visible and emits a redacted platform-log event. A production system should add a durable queue, retries, a dead-letter workflow and independent monitoring. No configured destination means **not_configured**, not delivered.

## Known scope boundaries

This version does not include email verification, password recovery, MFA, file uploads, real-time messaging, rich HTML, guaranteed notification delivery, or proven distributed-attack resilience. User management and conversations are intentionally capped. Concurrent permission changes may overlap requests already authorized; this should be hardened further before use with sensitive data. Test TLS, headers, trusted client IP, platform limits and webhook behavior on the actual deployment.
