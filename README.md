# OWASP Top 10 Demo

A Java 21 web app that shows each OWASP Top 10 (2021) vulnerability. Every page has two panels. One is broken. One is fixed. You can see both work in real time.

## Stack

- Java 21, Gradle 8
- Apache Tomcat 10.1 (embedded)
- H2 in-memory database
- jOOQ for queries
- Tailwind CSS via CDN

## Run

```bash
./gradlew run
```

Open `http://localhost:8090`. Log in with `admin / admin123`.

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
| A07 | Identification & Auth Failures    | `/auth-failures`   |
| A08 | Software & Data Integrity Failures| `/integrity`       |
| A09 | Security Logging & Monitoring     | `/logging`         |
| A10 | Server-Side Request Forgery       | `/ssrf`            |

## Safety

This app is a local-only playground. It binds to `127.0.0.1` only. Dangerous payloads (SSRF to private IPs, RCE on non-demo hosts) are simulated — the server shows what would happen without executing it.

## Configuration

Two YAML files hold the strings. Java code holds none of these.

- `application.yml` — settings. Port, bind address, credentials, session timeout, cookie `SameSite`, security headers, SSRF and RCE allowlists, lockout limits, OTP code. The HMAC secret lives here too. Never use the default in a real app.
- `messages.yml` — page text. Titles, tags, explanation and mitigation text, panel labels, and the dashboard cards.

Exploit payloads and form markup stay in the handlers.

## Sessions and audit

Login rotates the session ID. The cookie is `HttpOnly` and `SameSite=Lax`. Sessions expire after 30 minutes idle. Each login writes a row to the `sessions` table. It stores a SHA-256 hash of the ID, not the ID.

Every demo request writes a row to `audit_log`. Open `/db-browser` to read it.

## Docs

- [docs/design.md](docs/design.md) — routes, architecture, demo details
