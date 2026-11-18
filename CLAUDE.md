# CLAUDE.md

This is a OWASP top vulnerabilities playground app.

See [README.md](README.md) for project overview and [docs/design.md](docs/design.md) for full route table and demo details.

Follow Hemingway style while writing docs.

## Commands

```bash
./gradlew run                          # start app on port 8090
./gradlew test                         # run all tests
./gradlew test --tests "com.owasp.demo.controller.SqlInjectionHandlerTest"
./gradlew test --tests "*.SqlInjectionHandlerTest.vulnerableEndpoint_isExploitableWithInjection"
./gradlew compileJava                  # compile only
./gradlew test --rerun                 # force re-run (skip up-to-date)
```

## Architecture

Plain Java 21, no Spring. Single servlet (`AppServlet`) mapped to `/*` dispatches by `"METHOD /path"` key. `RouteRegistry` builds the table at startup. It scans `com.owasp.demo.controller` with ClassGraph for `@Controller` classes. It registers each `@GetMapping` and `@PostMapping` method. Routes are static paths. There are no path variables.

**Use `req.getPathInfo()`**, not `getServletPath()`. With `/*` mapping, `getServletPath()` always returns `""` and causes redirect loops.

**jOOQ + H2 positional access.** H2 returns qualified column names (`"PUBLIC"."USERS"."ID"`). Name-based field lookup throws `IllegalArgumentException`. Use `r.get(0, Integer.class)`, `r.get(1, String.class)`, etc. — match the `SELECT` column order.

### Adding a demo

1. Create `controller/MyHandler.java`. Annotate the class with `@Controller`.
2. Annotate each route method with `@GetMapping("/foo")` or `@PostMapping("/foo/vulnerable")`. It takes `(HttpServletRequest, HttpServletResponse)`. The scan registers it. No manual wiring.
3. Add a card to the `cards:` list in `messages.yml`. Keep the list in OWASP ID order.
4. Add the demo's title, badge (id, name, tag), info text and panel labels to `messages.yml`. Read them with `Messages.get("foo.title")`.
5. Put each form in `templates/forms/foo-vulnerable.html` and `foo-mitigated.html`. Render it with `TemplateEngine.render("forms/…", Map.of(...))`.
6. Use `TemplateEngine.vulnerabilityBadge()`, `infoBox()`, and two `demoPanel()` calls — red for `/foo/vulnerable`, green for `/foo/mitigated`.

`RouteInterceptor` writes the audit row for you and `AuthInterceptor` enforces login (session cookie or Basic auth). Both run from `AppServlet` before and after each handler. Do not log demo requests in the handler. Settings go in `application.yml`, read with `AppConfig.get().getString("a.b")`. Full rules: `.claude/rules/new-demo.md`.

### Templates

`TemplateEngine` loads `.html` files from `src/main/resources/templates/` via classloader and caches them. It replaces `{key}` placeholders in one pass. Shell structure lives in files. Each demo form lives in `templates/forms/<demo>-vulnerable.html` and `-mitigated.html`; the handler passes escaped values with `TemplateEngine.render()`. Tables and result boxes are Java strings in handlers.

### Tests

Repository tests call `Database.init()` in `@BeforeAll` and hit real H2. Controller tests mock `HttpServletRequest`, `HttpServletResponse`, and `HttpSession` with Mockito.
