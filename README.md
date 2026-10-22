# Campus Helpdesk

We built Campus Helpdesk for our Web Security Lab project. The idea is to give students a simple way to ask for campus support while applying the security concepts covered in the lab.

Students can create private tickets, follow their progress and reply to the support team. Staff handle assigned requests, and administrators manage users, assignments and security activity.

**Live app:** [campushelpdeskteam.netlify.app](https://campushelpdeskteam.netlify.app/)


## Our team

| Name | Student ID |
| --- | --- |
| Muaz Ahmed | if24b241 |
| Mohamed Amin Kasmi | if24b120 |
| Mahmoud Hashkeil | if25b198 |
| Mateo Lamthi | if23b263 |

## What the app does

- Students can register, sign in, create tickets and view their own conversations.
- Staff can view their own or assigned tickets and reply. They can update ticket status only when assigned to that ticket.
- Support staff can add internal notes that are hidden from the requester, including when the requester is a staff member.
- Administrators can assign tickets, search users, change roles, block accounts and sign other users out remotely.
- The admin dashboard shows ticket workload, unassigned requests and recent security activity.
- Users can change their password or request a password reset. Sending reset emails requires a configured delivery webhook.

## Technologies

We use HTML, CSS and vanilla JavaScript for the frontend, with a Node.js API running through Netlify Functions. PostgreSQL stores accounts, tickets, replies, sessions and security records. The browser sends requests to the API rather than connecting directly to the database.

The tests use Node's built-in test runner and PGlite, an embedded PostgreSQL engine. No frontend framework or external script CDN is required.

## Security controls

Security checks run on the server, even when the interface also validates input.

| Area | What we implemented |
| --- | --- |
| SQL injection | Parameterized PostgreSQL queries keep user input separate from SQL commands. |
| XSS | User content is displayed as plain text through `textContent`. A restrictive Content Security Policy adds another layer of protection. |
| CSRF | State-changing requests require the configured origin, a custom request header and JSON. Authenticated changes also require a session-bound CSRF token. |
| Passwords | Passwords are salted and hashed with scrypt. The password policy requires 15–128 characters. |
| Sessions and cookies | Random session tokens are stored as hashes in the database. Production cookies use `Secure`, `HttpOnly`, `SameSite=Strict` and the `__Host-` prefix. Sessions expire after eight hours. |
| Access control | The API checks ticket ownership, staff assignment and administrator permissions. Changing a ticket ID does not grant access to another student's ticket. |
| Allowlists and blocking | Only expected fields, roles, categories and status values are accepted. Administrators can block accounts and revoke their sessions. |
| Abuse prevention | Shared database counters limit requests, sign-in attempts and ticket activity. Body-size limits, pagination and query timeouts reduce resource use. |
| Logging and alerts | Audit records track important actions and failures. Repeated failed logins create an alert; an optional HTTPS webhook can deliver it externally. |
| Password recovery | Reset tokens are hashed, expire after 30 minutes and work once. A completed reset invalidates existing sessions. |

We do not rely on a blacklist of SQL keywords or HTML tags. Parameterized queries, safe rendering and explicit validation handle those inputs without treating legitimate support text as executable code.

After ten failed logins for an email address, new sign-ins for that address are blocked until the 15-minute failure window expires, including attempts with the correct password. Existing sessions remain valid. This limits guessing but can also temporarily lock out a legitimate user targeted by an attacker.

Application rate limits help with abuse and resource exhaustion, but they do not guarantee protection against DDoS attacks. Hosting-level protection and monitoring are still needed. This project also does not claim to prevent every known CWE.

## Run locally

You need Node.js 24 and PostgreSQL. The included Docker Compose file runs PostgreSQL 17 locally if you have Docker Desktop.

### 1. Install dependencies

```sh
npm ci
```

### 2. Configure the environment

Copy `.env.example` to `.env`:

```sh
cp .env.example .env
```

On Windows PowerShell, use:

```powershell
Copy-Item .env.example .env
```

Generate a random value for `RATE_LIMIT_SECRET`:

```sh
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Paste that value into `.env`. The example database URL matches the local Docker configuration, and `APP_ORIGIN` should remain `http://localhost:8888` for local development. Never commit `.env` or database credentials.

### 3. Start the database and app

With Docker Desktop running:

```sh
docker compose up -d
npm run migrate
npm run dev
```

If you already have PostgreSQL, set `DATABASE_URL` to that database and skip the Docker command. The migration command applies the SQL files in `db/`.

Open [localhost:8888](http://localhost:8888). Register an account, then make it the first administrator using:

```sh
npm run admin -- your-email@example.com
```

Sign in again to access the admin features. Other users register as students; an administrator can assign staff roles through **People**. There are no preset admin credentials.

The Docker password is only for local development. Local HTTP uses a development cookie without `Secure`; the deployed app requires HTTPS and uses the production cookie settings.

