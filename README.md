# OWASP Top 10 Demo

A Java 21 web app that shows each OWASP Top 10 (2021) vulnerability. Every page has two panels. One is broken. One is fixed. You can see both work in real time.

## Stack

- Java 21, Gradle 8
- Apache Tomcat 10.1 (embedded), one virtual thread per request
- H2 in-memory database
- jOOQ for queries
- Tailwind CSS via CDN

## Run

```bash
./gradlew run
```

Open `http://localhost:8090`. Log in with `admin / admin123`.

## Call from curl

Every route accepts HTTP Basic auth. No cookie needed.

```bash
curl -u admin:admin123 http://localhost:8090/xss
```

A wrong password gets a 401. No credentials gets a redirect to `/login`. The curl lines in each exploit box already use `-u`.

## H2 console

Open `http://localhost:8090/h2-console`. Log in to the app first, or use Basic auth. The console then asks for the database login:

- JDBC URL: `jdbc:h2:mem:owaspdb;DB_CLOSE_DELAY=-1`
- User: `sa`, no password

It reads the live in-memory database, so you see `users`, `sessions` and `audit_log` as the app sees them. Turn it off with `h2_console.enabled: false` in `application.yml`.

## Access log

Every HTTP request is written to `logs/access_log.<date>.log`, one line each. A line holds the client address, the app user, the time, the request line, the status, the size and the time taken. It holds no headers, cookies or request bodies, so passwords stay out. Change the folder or the pattern under `access_log` in `application.yml`. `logs/` is git-ignored.

## Test

```bash
./gradlew test
```

## Vulnerabilities Covered

| ID  | Name                              | Path               |
|-----|-----------------------------------|--------------------|
| A01 | Broken Access Control             | `/bac`             |
| A01 | Cross-Site Request Forgery        | `/csrf`            |
| A02 | Cryptographic Failures            | `/crypto`          |
| A03 | Injection — SQL                   | `/sqli`            |
| A03 | Injection — XSS                   | `/xss`             |
| A03 | Injection — OS Command (RCE)      | `/rce`             |
| A04 | Insecure Design                   | `/insecure-design` |
| A05 | Security Misconfiguration         | `/misconfig`       |
| A06 | Vulnerable & Outdated Components  | `/vuln-components` |
| A06 | Java4Shell (CVE-2026-114938)      | `/java4shell`      |
| A07 | Identification & Auth Failures    | `/auth-failures`   |
| A08 | Software & Data Integrity Failures| `/integrity`       |
| A09 | Security Logging & Monitoring     | `/logging`         |
| A10 | Server-Side Request Forgery       | `/ssrf`            |

## Safety

This app is a local-only playground. It binds to `127.0.0.1` only. Dangerous payloads (SSRF to private IPs, RCE on non-demo hosts) are simulated — the server shows what would happen without executing it.

## Configuration

Passwords are stored as bcrypt hashes. The seed passwords in `application.yml` are hashed at startup. Set the cost with `auth.bcrypt_cost`.

Two YAML files hold the strings. Java code holds none of these.

- `application.yml` — settings. Port, bind address, credentials, session timeout, cookie `SameSite`, security headers, SSRF and RCE allowlists, lockout limits, OTP code. The HMAC secret lives here too. Never use the default in a real app.
- `messages.yml` — page text. Titles, tags, explanation and mitigation text, panel labels, and the dashboard cards.

Form markup lives in `src/main/resources/templates/forms/`. Exploit payloads stay in the handlers.

## Sessions and audit

Login rotates the session ID. The cookie is named `OWASP_SID` (`session.cookie_name`). It is `HttpOnly` and `SameSite=Lax`. Sessions expire after 5 minutes idle. Every request resets the clock. All tabs in one browser share the session cookie, so they share the session. Logout and timeout delete the `sessions` row. Each login writes a row to the `sessions` table. It stores a SHA-256 hash of the ID, not the ID.

Every demo request writes a row to `audit_log`. Open `/db-browser` to read it.

## Docs

- [docs/design.md](docs/design.md) — routes, architecture, demo details
