# OWASP Top 10 Demo App — Design

## Overview
A Java 21 web application using embedded Apache Tomcat and H2 in-memory database to demonstrate each OWASP Top 10 (2021) vulnerability. Each vulnerability has a dedicated page with a vulnerable endpoint and a mitigated endpoint, side by side.

---

## Tech Stack
| Concern        | Choice                          |
|----------------|---------------------------------|
| Language       | Java 21                         |
| Build          | Gradle 8                        |
| Web server     | Apache Tomcat 10.1 (embedded)   |
| Database       | H2 in-memory                    |
| UI             | Tailwind CSS via CDN            |
| Templates      | Java string-based layout util   |

---

## Project Structure
```
owasp/
├── build.gradle
├── settings.gradle
├── docs/
│   └── design.md
└── src/main/java/com/owasp/demo/
    ├── Main.java                    # Starts embedded Tomcat
    ├── AppServlet.java              # Single front-controller servlet
    ├── db/
    │   └── Database.java           # H2 setup + seed data
    ├── handler/
    │   ├── Handler.java            # Interface: handle(req, res, session)
    │   ├── IndexHandler.java       # Dashboard with 10 links
    │   ├── LoginHandler.java       # Login / logout
    │   ├── SqlInjectionHandler.java
    │   ├── XssHandler.java
    │   ├── BrokenAccessHandler.java
    │   ├── CryptoFailuresHandler.java
    │   ├── InsecureDesignHandler.java
    │   ├── SecurityMisconfigHandler.java
    │   ├── VulnerableComponentsHandler.java
    │   ├── AuthFailuresHandler.java
    │   ├── DataIntegrityHandler.java
    │   ├── LoggingMonitoringHandler.java
    │   └── SsrfHandler.java
    └── util/
        └── Layout.java             # Base HTML layout wrapping Tailwind
```

---

## Routing (all via AppServlet)

```
GET  /                          → IndexHandler (dashboard)
GET  /login                     → LoginHandler (form)
POST /login                     → LoginHandler (authenticate)
GET  /logout                    → LoginHandler (invalidate session)

GET  /sqli                      → SqlInjectionHandler (demo page)
POST /sqli/vulnerable           → SqlInjectionHandler (raw string concat query)
POST /sqli/mitigated            → SqlInjectionHandler (prepared statement)

GET  /xss                       → XssHandler (demo page)
POST /xss/vulnerable            → XssHandler (unsanitised echo)
POST /xss/mitigated             → XssHandler (HTML-escaped echo)

GET  /bac                       → BrokenAccessHandler (demo page)
GET  /bac/vulnerable            → BrokenAccessHandler (no role check)
GET  /bac/mitigated             → BrokenAccessHandler (role check enforced)

GET  /crypto                    → CryptoFailuresHandler (demo page)
POST /crypto/vulnerable         → CryptoFailuresHandler (MD5 / plaintext)
POST /crypto/mitigated          → CryptoFailuresHandler (bcrypt-style hash)

GET  /insecure-design           → InsecureDesignHandler (demo page)
POST /insecure-design/vulnerable → no rate-limit on OTP check
POST /insecure-design/mitigated  → rate-limited OTP check

GET  /misconfig                 → SecurityMisconfigHandler (demo page)
GET  /misconfig/vulnerable      → exposes stack trace + debug info
GET  /misconfig/mitigated       → generic error, no internals exposed

GET  /vuln-components           → VulnerableComponentsHandler (demo page)

GET  /auth-failures             → AuthFailuresHandler (demo page)
POST /auth-failures/vulnerable  → no lockout, weak session token
POST /auth-failures/mitigated   → lockout after 3 attempts, secure token

GET  /integrity                 → DataIntegrityHandler (demo page)
POST /integrity/vulnerable      → deserialise / eval untrusted input
POST /integrity/mitigated       → validated / signed input

GET  /logging                   → LoggingMonitoringHandler (demo page)
POST /logging/vulnerable        → silent on failed login
POST /logging/mitigated         → structured audit log on failed login

GET  /ssrf                      → SsrfHandler (demo page)
POST /ssrf/vulnerable           → fetches user-supplied URL server-side
POST /ssrf/mitigated            → allowlist-validated URL fetch
```

---

## Authentication
- Session-based login stored in `HttpSession`
- Seed user: `admin / admin123` (shown as hint on login page)
- All demo routes redirect to `/login` if no valid session
- Session attribute key: `user`

---

## Database Seed (H2)
Tables created on startup:
- `users(id, username, password_hash, role)`
- `products(id, name, price, description)`
- `audit_log(id, timestamp, event, details)`

---

## OWASP Top 10 Demos

| # | ID   | Name                                    | Vulnerable endpoint demo                        | Mitigated endpoint demo                        |
|---|------|-----------------------------------------|-------------------------------------------------|------------------------------------------------|
| 1 | A01  | Broken Access Control                   | Admin data returned without role check          | Role check enforced; 403 if not admin          |
| 2 | A02  | Cryptographic Failures                  | Password stored/compared as MD5 hex             | Password compared with SHA-256 + salt (demo)   |
| 3 | A03  | Injection (SQL)                         | `SELECT * FROM users WHERE name='"+input+"'`    | Prepared statement with `?` placeholder        |
| 4 | A04  | Insecure Design                         | OTP brute-forceable (no attempt limit)          | Counter per session; locked after 5 attempts   |
| 5 | A05  | Security Misconfiguration               | Full stack trace + H2 console exposed           | Generic 500 page, internals hidden             |
| 6 | A06  | Vulnerable & Outdated Components        | Info page listing deps with known CVEs          | Info page showing patched alternatives         |
| 7 | A07  | Identification & Auth Failures          | No account lockout, predictable session token   | Lockout after 3 bad attempts, random UUID token|
| 8 | A08  | Software & Data Integrity Failures      | Eval / deserialise raw user JSON                | HMAC-signed payload validation                 |
| 9 | A09  | Security Logging & Monitoring Failures  | Failed login produces no log                    | Failed login writes to `audit_log` table       |
| 10| A10  | Server-Side Request Forgery (SSRF)      | Server fetches any user-supplied URL            | URL validated against allowlist before fetch   |

---

## Layout
- `Layout.java` produces full HTML pages with Tailwind CDN
- Base layout: top nav (app name + logout link) + main content area
- Child pages inject a title string and a content HTML string
- No JSP — all HTML built in Java handlers
