# OWASP Top 10 Demo App — Design

## What It Is

A Java 21 web app. It runs on embedded Tomcat. It shows each OWASP Top 10 vulnerability. Each page has two panels: one vulnerable, one fixed.

---

## Stack

| Layer      | Choice                        |
|------------|-------------------------------|
| Language   | Java 21                       |
| Build      | Gradle 8                      |
| Server     | Apache Tomcat 10.1 (embedded), virtual threads |
| Database   | H2 in-memory                  |
| UI         | Tailwind CSS via CDN          |
| Templates  | HTML files + Java strings     |
| DB access  | jOOQ                          |
| Config     | SnakeYAML + application.yml   |
| Page text  | SnakeYAML + messages.yml      |

---

## Packages

```
com.owasp.demo/
├── Main.java              — starts Tomcat
├── AppServlet.java        — one servlet, runs interceptors, then the route handler
├── interceptor/           — AuthInterceptor (login + session touch), RouteInterceptor (headers + audit)
├── config/                — loads application.yml at startup
├── util/                  — ConfigUtil (dotted YAML lookup), Messages (loads messages.yml)
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

GET  /java4shell                 Java4Shell demo page and JVM exposure check
POST /java4shell/vulnerable      Base64 decode, no checks
POST /java4shell/mitigated       size and alphabet checked first

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

Login is session-based via `HttpSession`. Every protected route checks for a session. No session means redirect to `/login`.

The login page lists every user from the `users` table. A button fills the form. Passwords show on purpose. This is a local demo.

On login the app:

- Rotates the session ID with `changeSessionId()`. This stops session fixation.
- Writes a row to `sessions`. The row holds a SHA-256 hash of the ID, the user, and UTC timestamps. Each request moves `last_seen_at` and `expires_at` forward. `SessionCleanupListener` deletes the row when the session ends, by logout or by timeout.

Tabs in one browser share the session cookie, so they share one session. Opening `/login` while logged in redirects to the dashboard.

Tomcat names the cookie `OWASP_SID` (`session.cookie_name`), not `JSESSIONID`. It sets the cookie `HttpOnly` and `SameSite=Lax`. The curl lines in the exploit boxes use the same name. Sessions end after `session.timeout_minutes` idle. The `Secure` flag is off because the app runs on plain HTTP.

Requests with `Authorization: Basic` are checked against the `users` table. A valid pair opens a 60-second session with the user and role set. It writes no `sessions` row. A bad pair gets a 401 with `WWW-Authenticate`. This lets curl call any route with `-u user:password`. A session cookie, when present and valid, wins over the header.

The request filter still trusts the Tomcat session, not the `sessions` table.

---

## Database

The H2 web console runs at `/h2-console`. `Main` mounts H2's `JakartaWebServlet` there when `h2_console.enabled` is true. `ConsoleAuthFilter` sits in front and applies the same login rules as the rest of the app, so the console is not open to anonymous requests. It connects to the in-memory database in the same JVM. H2 also refuses non-local connections by default.

Four tables: `users`, `products`, `audit_log`, `sessions`. `Database.init()` creates them and seeds two users on startup. Seed values come from `application.yml`, not hardcoded.

Passwords are stored as bcrypt hashes. `PasswordHasher` wraps jBCrypt. The cost is `auth.bcrypt_cost` (default 10). Each hash has its own salt. Seeding hashes the config password once and skips users that already exist. Login, Basic auth and the demo logins call `UserRepository.findByUsernameAndPasswordSafe()`, which loads the user by name and checks the hash. An unknown name still burns one hash check, so timing does not reveal which names exist. The login page buttons read the demo passwords from config, because the database holds no clear text.

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
| 11 | A03 | OS Command Injection (RCE)    | sh -c string concat (demo host + ls only) | ProcessBuilder + regex allowlist |
| 12 | A01 | CSRF                          | Email change on cookie alone        | Per-session token, 403 without it   |
| 13 | A06 | Java4Shell (CVE-2026-114938)  | Untrusted Base64 straight to the decoder | Size + alphabet checks; patch or JVM flag is the real fix |

The Java4Shell page cannot trigger the bug. It lives in the JVM's native Base64 code. Instead `JvmExposureCheck` compares the running JVM with the advisory: Java line (17, 21, 25, 27), x86-64, AVX-512 VBMI CPU flags from `/proc/cpuinfo`, and the flags `-XX:-UseBASE64Intrinsics` or `-XX:UseAVX=2`. It cannot read the vendor patch level, so it never says "patched". The lists live under `java4shell` in `application.yml`. Source: Tenable's FAQ for CVE-2026-114938.

---

## Safety Guards

The app is a local-only playground. Three layers keep it from causing real harm:

| Guard | Where | What it does |
|-------|-------|--------------|
| Localhost binding | `Main.java` | Tomcat bound to `127.0.0.1`. Not reachable from the network. |
| SSRF pre-flight | `SsrfHandler.demoSafetyBlock()` | Blocks `file://`, loopback, link-local (169.254.x.x), and private IP ranges. Shows a simulation message instead of fetching. |
| SSRF allowlist origin check | `SsrfHandler.isHostAllowed()` | Parses the URL and compares scheme+host+port. Prevents `startsWith` bypass via subdomain spoofing. |
| RCE host allowlist | `RceHandler` | Only `localhost`, `example.com`, `127.0.0.1` run a real `ping`. Other valid hostnames show the constructed command without executing it. |
| Shell injection guard | `RceHandler` | The vulnerable side runs a real `sh -c` only for a demo host followed by `ls` commands, such as `localhost; ls -la`. Any other injected command, `$(…)`, backtick, redirect or non-demo host shows `INJECTION BLOCKED` and the constructed command, not executed. Patterns live under `rce` in `application.yml`. |
| HMAC secret in config | `application.yml` | Secret lives outside source. Change it before any shared deployment. |
| Security headers | `RouteInterceptor` | Headers from `security.headers` in `application.yml`. Default: `nosniff` and `X-Frame-Options: DENY`. |

---

## Audit Log

`RouteInterceptor` writes one `audit_log` row for every demo request. Login, logout and the dashboard are not logged.

| Event             | When                        |
|-------------------|-----------------------------|
| `DEMO_VIEW`       | A demo page is opened       |
| `DEMO_VULNERABLE` | The vulnerable path is used |
| `DEMO_MITIGATED`  | The mitigated path is used  |

Details read `user=… method=… path=… status=… params=…`. It lists parameter names only. Values are left out because demos receive passwords and secrets. A failed write never breaks the request.

---

## Access Log

`Main` adds Tomcat's `AccessLogValve` to the host. It writes `logs/access_log.<date>.log` with no buffering, and rotates daily. The default pattern is `%h %l %{user}s %t "%r" %s %b %{ms}Tms`. `%{user}s` reads the `user` attribute from the session, so Basic auth and form logins both show the app user. The pattern has no `%{Authorization}i`, no cookies and no bodies, so secrets never reach the file. Settings live under `access_log` in `application.yml`.

---

## Config and Text

`application.yml` holds settings. `messages.yml` holds page text. `ConfigUtil` reads both by dotted path, such as `session.same_site`. `Messages.get("xss.title")` returns page text. A missing key fails fast with its name.

---

## Templates

`TemplateEngine` loads `.html` files from `resources/templates/`. It swaps `{key}` placeholders in one pass, so user input that looks like `{other}` stays plain text.

The shell templates are `base.html`, `nav-auth.html`, `nav-public.html`, and `login.html`. Each demo form lives in `templates/forms/<demo>-vulnerable.html` or `<demo>-mitigated.html`. Handlers pass only the dynamic values, already escaped.

At startup the engine reads every file in `templates/forms/` into memory. It also keeps any other template after first use. Nothing is read from disk per request. It works from a classpath folder and from inside a jar.

Result boxes, tables and the panel layout are still Java strings in the handlers.
