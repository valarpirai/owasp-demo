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
| A01 | Cross-Site Request Forgery       | `/csrf`            |
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

Edit `src/main/resources/application.yml` to change port, credentials, SSRF allowlist, and lockout limits. The HMAC secret for the data integrity demo lives there too — never use the default in a real app.

## Docs

- [docs/design.md](docs/design.md) — routes, architecture, demo details
