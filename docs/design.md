# OWASP Top 10 Demo App — Design

## What It Is

A Java 21 web app. It runs on embedded Tomcat. It shows each OWASP Top 10 vulnerability. Each page has two panels: one vulnerable, one fixed.

---

## Stack

| Layer      | Choice                        |
|------------|-------------------------------|
| Language   | Java 21                       |
| Build      | Gradle 8                      |
| Server     | Apache Tomcat 10.1 (embedded) |
| Database   | H2 in-memory                  |
| UI         | Tailwind CSS via CDN          |
| Templates  | HTML files + Java strings     |
| DB access  | jOOQ                          |
| Config     | SnakeYAML + application.yml   |

---

## Packages

```
com.owasp.demo/
├── Main.java              — starts Tomcat
├── AppServlet.java        — one servlet, routes all requests
├── config/                — loads application.yml at startup
├── controller/            — one handler per vulnerability
├── model/                 — User, Product, AuditLog records
├── repository/            — jOOQ queries; one class per table
├── db/                    — H2 connection + schema init
└── view/                  — TemplateEngine; loads HTML from resources
```

---

## Routes

All routes go through `AppServlet`. It reads `req.getPathInfo()` and matches `"METHOD /path"`.

```
GET  /                           dashboard
GET  /login                      login form
POST /login                      authenticate
GET  /logout                     end session

GET  /sqli                       SQL injection demo page
POST /sqli/vulnerable            raw string concat query
POST /sqli/mitigated             prepared statement

GET  /xss                        XSS demo page
POST /xss/vulnerable             raw echo
POST /xss/mitigated              HTML-escaped echo

GET  /bac                        broken access control demo page
GET  /bac/vulnerable             no role check
GET  /bac/mitigated              role check enforced

GET  /csrf                       CSRF demo page
GET  /csrf/attack                attacker page, auto-posts a forged form
POST /csrf/vulnerable            cookie only, no token
POST /csrf/mitigated             per-session token required

GET  /crypto                     crypto failures demo page
POST /crypto/vulnerable          MD5, no salt
POST /crypto/mitigated           SHA-256 + random salt

GET  /insecure-design            insecure design demo page
POST /insecure-design/vulnerable no OTP attempt limit
POST /insecure-design/mitigated  locked after 5 attempts

GET  /misconfig                  security misconfiguration demo page
GET  /misconfig/vulnerable       full stack trace returned
GET  /misconfig/mitigated        generic error, nothing exposed

GET  /vuln-components            known CVEs in listed dependencies

GET  /auth-failures              auth failures demo page
POST /auth-failures/vulnerable   no lockout, predictable token
POST /auth-failures/mitigated    lockout + UUID token

GET  /integrity                  data integrity demo page
POST /integrity/vulnerable       no signature check
POST /integrity/mitigated        HMAC-SHA256 verified

GET  /logging                    logging demo page
POST /logging/vulnerable         failed login logged nowhere
POST /logging/mitigated          failed login written to audit_log

GET  /ssrf                       SSRF demo page
POST /ssrf/vulnerable            fetches any URL (loopback/private blocked by safety guard)
POST /ssrf/mitigated             allowlist blocks non-approved origins

GET  /rce                        OS command injection demo page
POST /rce/vulnerable             sh -c with user input (demo hosts only; others simulated)
POST /rce/mitigated              ProcessBuilder arg array + hostname allowlist
```

---

## Auth

Login is session-based via `HttpSession`. The seed admin is `admin / admin123`. Every protected route checks for a session. No session means redirect to `/login`.

---

## Database

Three tables: `users`, `products`, `audit_log`. `Database.init()` creates them and seeds two users on startup. Seed values come from `application.yml`, not hardcoded.

---

## OWASP Demos

| #  | ID  | Name                          | Vulnerable shows                    | Mitigated shows                     |
|----|-----|-------------------------------|-------------------------------------|-------------------------------------|
| 1  | A01 | Broken Access Control         | All users + passwords, no role check | 403 for non-admin                   |
| 2  | A02 | Cryptographic Failures        | MD5 hash, no salt                   | SHA-256 + random salt               |
| 3  | A03 | Injection (SQL)               | String concat query                 | Prepared statement                  |
| 4  | A04 | Insecure Design               | Unlimited OTP guesses               | Locked after 5 wrong attempts       |
| 5  | A05 | Security Misconfiguration     | Full stack trace in response        | Generic error page                  |
| 6  | A06 | Vulnerable Components         | Deps with known CVEs listed         | Fixed versions shown                |
| 7  | A07 | Auth Failures                 | No lockout, timestamp-based token   | 3-attempt lockout, UUID token       |
| 8  | A08 | Data Integrity Failures       | Accepts any Base64 payload          | Rejects payload with bad HMAC       |
| 9  | A09 | Logging Failures              | Failed login silent                 | Failed login in audit_log           |
| 10 | A10 | SSRF                          | Fetches any URL (safety guard for private IPs) | Allowlist by parsed origin |
| 11 | A03 | OS Command Injection (RCE)    | sh -c string concat (demo hosts only) | ProcessBuilder + regex allowlist |

---

## Safety Guards

The app is a local-only playground. Three layers keep it from causing real harm:

| Guard | Where | What it does |
|-------|-------|--------------|
| Localhost binding | `Main.java` | Tomcat bound to `127.0.0.1`. Not reachable from the network. |
| SSRF pre-flight | `SsrfHandler.demoSafetyBlock()` | Blocks `file://`, loopback, link-local (169.254.x.x), and private IP ranges. Shows a simulation message instead of fetching. |
| SSRF allowlist origin check | `SsrfHandler.isHostAllowed()` | Parses the URL and compares scheme+host+port. Prevents `startsWith` bypass via subdomain spoofing. |
| RCE host allowlist | `RceHandler` | Only `localhost`, `example.com`, `127.0.0.1` run a real `ping`. Other valid hostnames show the constructed command without executing it. |
| Shell injection guard | `RceHandler` | Any input that fails the `[a-zA-Z0-9._-]` regex shows `INJECTION DETECTED` and the constructed command, not executed. |
| HMAC secret in config | `application.yml` | Secret lives outside source. Change it before any shared deployment. |
| Security headers | `AppServlet` | `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` on every response. |

---

## Templates

`TemplateEngine` loads `.html` files from `resources/templates/` at runtime. It swaps `{key}` placeholders. The shell templates are `base.html`, `nav-auth.html`, `nav-public.html`, and `login.html`. Everything else — forms, tables, result boxes — is built as Java strings in the handlers.
