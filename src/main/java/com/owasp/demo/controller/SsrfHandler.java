package com.owasp.demo.controller;

import com.owasp.demo.config.AppConfig;
import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

public class SsrfHandler implements IRouteHandler {

    private static final HttpClient HTTP = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .build();

    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String path = req.getServletPath();

        if ("POST".equals(req.getMethod()) && "/ssrf/vulnerable".equals(path)) {
            handleVulnerable(req, res);
        } else if ("POST".equals(req.getMethod()) && "/ssrf/mitigated".equals(path)) {
            handleMitigated(req, res);
        } else {
            renderPage(res, null, null);
        }
    }

    private void handleVulnerable(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String url = req.getParameter("url");
        String result;
        try {
            HttpRequest httpReq = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(5))
                .GET().build();
            HttpResponse<String> httpRes = HTTP.send(httpReq, HttpResponse.BodyHandlers.ofString());
            String body = httpRes.body().length() > 500
                ? httpRes.body().substring(0, 500) + "…"
                : httpRes.body();
            result = "<strong>Status:</strong> " + httpRes.statusCode() + "<br/>" +
                     "<strong>Body (truncated):</strong><br/><pre class='text-xs bg-gray-100 p-2 mt-1 rounded overflow-auto'>" +
                     TemplateEngine.escape(body) + "</pre>";
        } catch (Exception e) {
            result = "Error fetching URL: " + TemplateEngine.escape(e.getMessage());
        }
        renderPage(res, result, null);
    }

    private void handleMitigated(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String url = req.getParameter("url2");
        List<String> allowlist = AppConfig.get().getSsrfAllowlist();
        String result;

        boolean allowed = allowlist.stream().anyMatch(url::startsWith);
        if (!allowed) {
            result = "<span class='text-red-600 font-semibold'>Blocked — URL not in allowlist.</span><br/>" +
                     "<span class='text-xs text-gray-600'>Allowed prefixes: " +
                     TemplateEngine.escape(String.join(", ", allowlist)) + "</span>";
            renderPage(res, null, result);
            return;
        }

        try {
            HttpRequest httpReq = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(5))
                .GET().build();
            HttpResponse<String> httpRes = HTTP.send(httpReq, HttpResponse.BodyHandlers.ofString());
            String body = httpRes.body().length() > 500
                ? httpRes.body().substring(0, 500) + "…"
                : httpRes.body();
            result = "<strong>Status:</strong> " + httpRes.statusCode() + "<br/>" +
                     "<strong>Body (truncated):</strong><br/><pre class='text-xs bg-gray-100 p-2 mt-1 rounded overflow-auto'>" +
                     TemplateEngine.escape(body) + "</pre>";
        } catch (Exception e) {
            result = "Error fetching URL: " + TemplateEngine.escape(e.getMessage());
        }
        renderPage(res, null, result);
    }

    private void renderPage(HttpServletResponse res, String vulnResult, String safeResult) throws IOException {
        List<String> allowlist = AppConfig.get().getSsrfAllowlist();

        String info = TemplateEngine.infoBox(
            "The server fetches any URL provided by the user. An attacker can supply internal " +
            "addresses like <code>http://169.254.169.254/latest/meta-data/</code> (cloud metadata) " +
            "or <code>http://localhost:8080/admin</code> to access services not exposed externally.",
            "Validate URLs against a strict allowlist of approved domains/prefixes before fetching. " +
            "Block private IP ranges and loopback addresses. The allowlist is configurable in " +
            "<code>application.yml</code> under <code>ssrf.allowlist</code>."
        );

        String vulnForm = """
            <form method="POST" action="/ssrf/vulnerable" class="space-y-3">
              <label class="block text-sm font-medium text-gray-700">URL to fetch</label>
              <input type="text" name="url" placeholder="https://example.com"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"/>
              <p class="text-xs text-gray-500">Try: <code>http://localhost:8080/</code> or <code>file:///etc/passwd</code></p>
              <button class="bg-red-600 text-white px-4 py-2 rounded text-sm hover:bg-red-700">Fetch (No Validation)</button>
            </form>
            """;

        String safeForm = """
            <form method="POST" action="/ssrf/mitigated" class="space-y-3">
              <label class="block text-sm font-medium text-gray-700">URL to fetch</label>
              <input type="text" name="url2" placeholder="%s"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"/>
              <p class="text-xs text-gray-500">Allowlist: <code>%s</code></p>
              <button class="bg-green-600 text-white px-4 py-2 rounded text-sm hover:bg-green-700">Fetch (Allowlist)</button>
            </form>
            """.formatted(
                allowlist.isEmpty() ? "https://example.com" : allowlist.getFirst(),
                TemplateEngine.escape(String.join(", ", allowlist))
            );

        String panels = """
            <div class="grid md:grid-cols-2 gap-6">%s%s</div>
            """.formatted(
                TemplateEngine.demoPanel("Vulnerable — Fetch Any URL", "red", vulnForm,
                    vulnResult != null ? TemplateEngine.resultBox(vulnResult, false) : ""),
                TemplateEngine.demoPanel("Mitigated — Allowlist Enforced", "green", safeForm,
                    safeResult != null ? TemplateEngine.resultBox(safeResult, true) : "")
            );

        String content = TemplateEngine.vulnerabilityBadge("A10", "Server-Side Request Forgery (SSRF)") + info + panels;
        res.getWriter().write(TemplateEngine.page("SSRF", content, true));
    }
}
