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

Sign in again. Register separate student and staff accounts, promote the support account through **People**, and assign tickets through their details pages. Staff only see their own or assigned tickets; administrators see all tickets.

The compose database password is for local development only. The local HTTP cookie intentionally omits `Secure`; production requires HTTPS and uses a `__Host-` cookie. This app is not a browser-only demo: sign-in and tickets require a working database and valid environment configuration.

## Verification

```sh
npm run check
npm test
npm run test:integration
npm audit --omit=dev --audit-level=high
```

Integration tests run in an isolated, in-memory PostgreSQL engine and do not use your live database. They cover SQL payload storage, ownership checks, assigned staff, CSRF, content types, privilege fields, session rotation/logout/expiry, blocked accounts, login alerts, rate limiting, and database failures. These are regression tests, not a penetration-test certification or proof of DDoS resistance.

## Deploy to Netlify

1. Create a [Neon](https://console.neon.tech) project (Postgres 16+, region close to your Netlify Functions region, e.g. `aws-us-east-2`). From **Connect**, copy two connection strings: the **pooled** one (host contains `-pooler`) for the app, and the **direct** one for migrations. Keep `sslmode=require` — do not disable certificate verification.
2. Apply the schema from your machine with the direct connection:

   ```sh
   MIGRATION_DATABASE_URL='<direct Neon URL>' DATABASE_URL='<pooled Neon URL>' npm run migrate
   ```

   For least privilege, create a separate runtime role in Neon with only SELECT/INSERT/UPDATE/DELETE on these tables and use it in the pooled `DATABASE_URL`.
3. Import this GitHub repository into Netlify. `netlify.toml` configures `public` and `netlify/functions`. This is a Git-based Functions deployment; uploading only `public` will not deploy the backend.
4. Set server-side environment variables for Functions (Site configuration → Environment variables, scope **Functions**): `DATABASE_URL` (the pooled Neon URL), `APP_ORIGIN` (exact HTTPS origin without a trailing slash), `RATE_LIMIT_SECRET` (random 32+ characters), and `NODE_ENV=production`. Optionally set `ALERT_WEBHOOK_URL` to your team's HTTPS JSON receiver. Never expose these as frontend configuration.
5. Deploy, register the initial administrator account, and run the admin command locally against the target database using protected environment variables.
6. Verify registration, login, logout, two-user isolation, staff assignment, CSRF rejection, headers, cookies, alert delivery, and log access on the deployed URL. Review hosting traffic controls, usage limits, monitoring and spend alerts for your actual Netlify plan.
7. Replace the deployment placeholder above and fill in team names. Keep previews isolated from production data and secrets; their origin must match their own configuration.

Netlify static headers are configured separately from API response headers. Check both on the deployed site. Netlify Functions are ephemeral, so the app does not rely on in-memory sessions or per-instance rate counters.

## Security design

See [security controls](docs/SECURITY-CONTROLS.md), [threat model](docs/THREAT-MODEL.md), and [lab demonstration](docs/LAB-DEMO.md).

The project uses defense in depth against relevant weaknesses. It does **not** claim protection against every CWE or immunity to DDoS. Email ownership verification, password recovery, MFA, durable notification retries, and large-scale operations are outside this first implementation. Do not use it for sensitive real-world support cases without further review.

## Repository workflow

Use focused branches and conventional commits, for example `feat(tickets): add assigned staff workflow` or `fix(auth): revoke blocked account sessions`. Run the checks before committing, review the diff, and submit a pull request with behavior and test evidence. Do not commit credentials, real ticket contents, or log exports containing personal data.

## References

- [Netlify Functions](https://docs.netlify.com/build/functions/overview/)
- [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

Academic project. Team and deployment information remain to be completed before submission.
