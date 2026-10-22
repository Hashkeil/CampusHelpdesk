# Deployment verification

Target: https://campushelpdeskteam.netlify.app/

Checked: 2026-10-22 (Europe/Vienna)

- Frontend: HTTP 200.
- Static headers: CSP, HSTS, nosniff, frame denial, referrer policy, and permissions policy present.
- API function: deployed and reachable, but `/api/auth/me` returns HTTP 500 before database/environment configuration.
- Current deployment is not ready for authenticated use until PostgreSQL is provisioned and the schema and runtime environment are configured.
- Automated checks passed locally: four unit tests and eleven API scenarios against embedded PostgreSQL.
- Production registration, login, ticket isolation, staff/admin workflows, cookies and alert delivery still require verification.

This record will be updated after configuration. Do not represent pending checks as passed.
