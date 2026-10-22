# Lab demonstration and submission checklist

Only use accounts and environments owned by the group. Do not run floods against Netlify or a shared service.

1. Register Alice, Bob and a support user. Bootstrap a separate administrator using the CLI. Assign the support role in People.
2. Alice creates a ticket. Copy its URL identifier from the API request. Verify Bob receives 404 for detail and reply requests and cannot list Alice's ticket.
3. Assign the ticket to the support user. Demonstrate that only assigned staff can access it; update its status and add a reply.
4. Use `<img src=x onerror=alert(1)>` in a ticket title. Show that it is displayed as text without an alert. Use `' OR 1=1 --` in search and show that it does not expand access.
5. Inspect the production session cookie: Secure, HttpOnly, SameSite=Strict and __Host prefix. Show that logout invalidates it server-side.
6. In a controlled API test, remove the CSRF token, change Origin, or send a role field during registration. Show rejection.
7. Run the isolated integration suite for rate limiting rather than load-testing public hosting.
8. Trigger five failed logins in the controlled environment and inspect the audit and alert records. Configure a team-owned test receiver and verify delivery; test an unreachable receiver and inspect `failed`. No destination must show `not_configured`.
9. Block Bob through People and demonstrate that his existing session stops working.
10. Capture test results and deployed response headers. Record the exact Git commit, date, deployed URL, observed results and known limitations.

Before submission: fill in the README team table and deployment URL, run CI, inspect the repository for secrets, verify actual database TLS and runtime permissions, and include test evidence. Do not present unexecuted deployment checks as passed.
