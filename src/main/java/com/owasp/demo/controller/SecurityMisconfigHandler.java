package com.owasp.demo.controller;

import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public class SecurityMisconfigHandler implements IRouteHandler {

    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String path = req.getPathInfo();

        if ("/misconfig/vulnerable".equals(path)) {
            handleVulnerable(req, res);
        } else if ("/misconfig/mitigated".equals(path)) {
            handleMitigated(req, res);
        } else {
            renderPage(res, null, null);
        }
    }

    private void handleVulnerable(HttpServletRequest req, HttpServletResponse res) throws IOException {
        try {
            throw new RuntimeException("DB connection failed: jdbc:h2:mem:owaspdb;user=sa;password=");
        } catch (RuntimeException e) {
            StringBuilder sb = new StringBuilder();
            sb.append("<strong class='text-red-600'>500 Internal Server Error</strong><br/>");
            sb.append("<pre class='text-xs bg-gray-100 p-2 mt-2 overflow-auto rounded'>")
              .append(TemplateEngine.escape(e.getMessage())).append("\n");
            for (StackTraceElement el : e.getStackTrace()) {
                sb.append("  at ").append(TemplateEngine.escape(el.toString())).append("\n");
            }
            sb.append("</pre>");
            sb.append("<p class='text-xs text-red-600 mt-2'>DB URL, class names, and line numbers are exposed!</p>");
            renderPage(res, sb.toString(), null);
        }
    }

    private void handleMitigated(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String result =
            "<strong class='text-gray-700'>500 Internal Server Error</strong><br/>" +
            "<p class='text-sm text-gray-600 mt-1'>Something went wrong. Please try again later.</p>" +
            "<p class='text-xs text-green-600 mt-2'>Stack trace is logged server-side only. No internals exposed to client.</p>";
        renderPage(res, null, result);
    }

    private void renderPage(HttpServletResponse res, String vulnResult, String safeResult) throws IOException {
        String info = TemplateEngine.infoBox(
            "The application exposes full stack traces, internal class names, file paths, and " +
            "database connection strings to the browser on error. This gives attackers a detailed " +
            "map of the application internals to plan further attacks.",
            "Return generic error pages to clients (HTTP 500 with no internal details). " +
            "Log the full exception server-side only. Disable debug/verbose error modes in production. " +
            "Scan for exposed admin consoles (e.g. H2 web console, Actuator endpoints)."
        );

        String vulnBtn = """
            <a href="/misconfig/vulnerable"
               class="inline-block bg-red-600 text-white px-4 py-2 rounded text-sm hover:bg-red-700">
              Trigger Error (Verbose)
            </a>
            %s
            """.formatted(vulnResult != null ? "<div class='mt-3'>" + vulnResult + "</div>" : "");

        String safeBtn = """
            <a href="/misconfig/mitigated"
               class="inline-block bg-green-600 text-white px-4 py-2 rounded text-sm hover:bg-green-700">
              Trigger Error (Safe)
            </a>
            %s
            """.formatted(safeResult != null ? "<div class='mt-3'>" + safeResult + "</div>" : "");

        String panels = """
            <div class="grid md:grid-cols-2 gap-6">%s%s</div>
            """.formatted(
                TemplateEngine.demoPanel("Vulnerable — Stack Trace Exposed", "red", vulnBtn, ""),
                TemplateEngine.demoPanel("Mitigated — Generic Error Page", "green", safeBtn, "")
            );

        String exploits = TemplateEngine.exploitBox(new String[][]{
            {"Trigger verbose error", "GET /misconfig/vulnerable",
             "Click the vulnerable button — the response leaks DB URL, class names, and full stack trace.",
             null,
             "curl -s http://localhost:8090/misconfig/vulnerable -b 'JSESSIONID=SESSION'"},
            {"H2 console access", "GET /h2-console",
             "Many Spring Boot apps expose the H2 web console in production. Try browsing to /h2-console directly.",
             null,
             "curl -s http://localhost:8090/h2-console -b 'JSESSIONID=SESSION' -I"},
            {"Default credentials", "sa / (empty password)",
             "H2's default SA user has no password. Combined with an exposed console, full DB access is trivial.",
             null,
             "curl -s http://localhost:8090/h2-console/login.do -X POST -d 'url=jdbc:h2:mem:owaspdb&user=sa&password='"},
        });

        String content = TemplateEngine.vulnerabilityBadge("A05", "Security Misconfiguration") + info + exploits + panels;
        res.getWriter().write(TemplateEngine.page("Security Misconfiguration", content, true));
    }
}
