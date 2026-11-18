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

Plain Java 21, no Spring. Single servlet (`AppServlet`) mapped to `/*` dispatches by `"METHOD /path"` key to `IRouteHandler` impls.

**Use `req.getPathInfo()`**, not `getServletPath()`. With `/*` mapping, `getServletPath()` always returns `""` and causes redirect loops.

**jOOQ + H2 positional access.** H2 returns qualified column names (`"PUBLIC"."USERS"."ID"`). Name-based field lookup throws `IllegalArgumentException`. Use `r.get(0, Integer.class)`, `r.get(1, String.class)`, etc. — match the `SELECT` column order.

### Adding a demo

1. Create `controller/MyHandler.java` implementing `IRouteHandler`.
2. Register routes in `AppServlet`'s constructor.
3. Add a card to `IndexHandler.CARDS`.
4. Use `TemplateEngine.vulnerabilityBadge()`, `infoBox()`, and two `demoPanel()` calls — red for `/foo/vulnerable`, green for `/foo/mitigated`.

### Templates

`TemplateEngine` loads `.html` files from `src/main/resources/templates/` via classloader. It replaces `{key}` placeholders. Shell structure lives in files. Forms and tables are Java strings in handlers.

### Tests

Repository tests call `Database.init()` in `@BeforeAll` and hit real H2. Controller tests mock `HttpServletRequest`, `HttpServletResponse`, and `HttpSession` with Mockito.
