# Campus Helpdesk

A campus support application built for a Web Security Lab assessment. Students submit private requests, assigned staff respond, and administrators manage access and review security activity.

**Deployment:** Hosted on Netlify at **https://campushelpdeskteam.netlify.app/**. Production branch: `feat/secure-campus-helpdesk`. See `docs/DEPLOYMENT-VERIFICATION.md` for the latest verified readiness status.

## Team

| Name | Student ID |
| --- | --- |
| Muaz Ahmed | if24b241 |
| Mohamed Amin Kasmi | if24b120 |
| Mahmoud Hashkeil | if25b198 |
| Mateo Lamthi | if23b263

## Stack

- HTML, CSS, and vanilla JavaScript frontend; no CDN scripts or remote fonts.
- Node.js 24 / JavaScript API deployed as Netlify Functions.
- PostgreSQL for accounts, sessions, tickets, audit events, and shared rate limits.
- Node's built-in test runner and PGlite for API tests against an embedded PostgreSQL engine.

## Local setup

Requirements: Node.js 24 and PostgreSQL 17 (or Docker Desktop).

```sh
npm ci
cp .env.example .env
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

On PowerShell, use `Copy-Item .env.example .env`. Paste the generated random value into `RATE_LIMIT_SECRET` in `.env`. Never commit `.env`.

Start Docker Desktop, then:

```sh
docker compose up -d
npm run migrate
npm run dev
```

Open **http://localhost:8888**. Register an account. To make it the initial administrator:

```sh
npm run admin -- your-email@example.com
```

Sign in again. **Admin overview** shows open and unassigned requests, staff workload and the last day's failed sign-ins. Register separate student and staff accounts, promote the support account through **People** (searchable, filterable by role, with remote sign-out), and assign tickets through their details pages. **Security activity** lists alerts and a filterable audit log. Staff only see their own or assigned tickets; administrators see all tickets.

The compose database password is for local development only. The local HTTP cookie intentionally omits `Secure`; production requires HTTPS and uses a `__Host-` cookie. This app is not a browser-only demo: sign-in and tickets require a working database and valid environment configuration.

## Verification

```sh
npm run check
npm test
npm run test:integration
npm audit --omit=dev --audit-level=high
```

Integration tests run in an isolated, in-memory PostgreSQL engine and do not use your live database. They cover SQL payload storage, ownership checks, assigned staff, CSRF, content types, privilege fields, session rotation/logout/expiry, blocked accounts, login alerts, rate limiting, and database failures. These are regression tests, not a penetration-test certification or proof of DDoS resistance.
