# Rules for adding a vulnerability demo

Follow these rules for every new demo. `CsrfHandler` is the reference.

## Shape

- One handler per demo, in `controller/`, implementing `IRouteHandler`.
- Routes: `GET /foo` (page), `POST /foo/vulnerable`, `POST /foo/mitigated`.
- Read the path with `req.getPathInfo()`. Never `getServletPath()`.
- Every demo has a vulnerable side and a mitigated side. No exceptions.

## Wiring

1. Register every route in the `AppServlet` constructor.
2. Add a card to the `cards:` list in `messages.yml`, in OWASP ID order.
3. Add a row to the table in `README.md`.
4. Add the routes to `docs/design.md`.

## Page

- Put titles, tag, info text and panel labels in `messages.yml`. Read them with `Messages.get()`. No page text in Java.
- Put settings in `application.yml`. Read them with `AppConfig.get()`.
- Build the page with `TemplateEngine`: `vulnerabilityBadge()`, `infoBox()`, `exploitBox()`.
- Use two `demoPanel()` calls. Red is vulnerable. Green is mitigated.
- Escape every user value with `TemplateEngine.escape()`. The vulnerable side may skip it only when the flaw is the missing escape.
- Show ready payloads in `exploitBox()`, with a curl line.

## Audit

- `RouteInterceptor` logs every demo request to `audit_log`. Do not add your own log call.
- Never put secrets in a handler's parameter names. Values are not logged.

## Safety

- The app is local-only. Simulate anything dangerous. Do not run it.
- No real network calls to outside hosts. No real file or process damage.
- Keep state in the session or H2. Never write to disk.

## Data

- Query through a repository class. Use jOOQ.
- Read columns by position, in `SELECT` order. H2 returns qualified names.
- Avoid schema changes unless the demo needs them.

## Tests

- One `XxxHandlerTest` per handler. Mock request, response and session with Mockito.
- Prove the vulnerable side is exploitable.
- Prove the mitigated side blocks the same attack.
- Prove the GET page renders both forms.
- Run `./gradlew test` before you commit.

## Docs

- Hemingway style. Short sentences. Plain words.
- Say what the code does.
- Keep each doc under 250 lines.
