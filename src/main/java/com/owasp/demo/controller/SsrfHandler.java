package com.owasp.demo.controller;

import com.owasp.demo.util.Messages;
import com.owasp.demo.config.AppConfig;
import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.InetAddress;
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
        String path = req.getPathInfo();

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

        String blocked = demoSafetyBlock(url);
        if (blocked != null) {
            result = blocked;
            renderPage(res, result, null);
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
        renderPage(res, result, null);
    }

    /**
     * Returns a simulated block message for URLs that would cause real harm if fetched.
     * file://, loopback, link-local, and private ranges are all blocked.
     * Returns null when the URL is safe to actually fetch.
     */
    static String demoSafetyBlock(String url) {
        try {
            URI uri = URI.create(url);
            String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase() : "";
            if (!scheme.equals("http") && !scheme.equals("https")) {
                return "[DEMO SAFETY BLOCK — scheme '" + scheme + "' not allowed]\n\n" +
                       "A real vulnerable server would fetch this URL, reading local files or triggering " +
                       "protocol-level attacks. This demo blocks non-http(s) schemes to stay safe.";
            }
            String host = uri.getHost();
            if (host != null) {
                InetAddress addr = InetAddress.getByName(host);
                if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() || addr.isLinkLocalAddress()) {
                    return "[DEMO SAFETY BLOCK — '" + host + "' resolves to a private/loopback address]\n\n" +
                           "A real vulnerable server would reach internal services at this address, " +
                           "including cloud metadata endpoints (169.254.169.254) or services on localhost.";
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    /** Checks the parsed host matches an allowlisted origin — prevents startsWith bypass via subdomains. */
    static boolean isHostAllowed(String url, List<String> allowlist) {
        try {
            URI uri = URI.create(url);
            String origin = uri.getScheme() + "://" + uri.getHost()
                + (uri.getPort() != -1 ? ":" + uri.getPort() : "");
            return allowlist.stream().anyMatch(entry -> {
                try {
                    URI allowed = URI.create(entry);
                    String allowedOrigin = allowed.getScheme() + "://" + allowed.getHost()
                        + (allowed.getPort() != -1 ? ":" + allowed.getPort() : "");
                    return origin.equalsIgnoreCase(allowedOrigin);
                } catch (Exception e) {
                    return false;
                }
            });
        } catch (Exception e) {
            return false;
        }
    }

    private void handleMitigated(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String url = req.getParameter("url2");
        List<String> allowlist = AppConfig.get().getSsrfAllowlist();
        String result;

        boolean allowed = isHostAllowed(url, allowlist);
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
            Messages.get("ssrf.info.explanation"),
            Messages.get("ssrf.info.mitigation")
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
                TemplateEngine.demoPanel(Messages.get("ssrf.panel.vulnerable"), "red", vulnForm,
                    vulnResult != null ? TemplateEngine.resultBox(vulnResult, false) : ""),
                TemplateEngine.demoPanel(Messages.get("ssrf.panel.mitigated"), "green", safeForm,
                    safeResult != null ? TemplateEngine.resultBox(safeResult, true) : "")
            );

        String exploits = TemplateEngine.exploitBox(new String[][]{
            {"Loopback probe", "http://localhost:8090/",
             "Forces the server to fetch its own home page — probes internal services not exposed externally.", "url",
             "curl -s -X POST http://localhost:8090/ssrf/vulnerable -b 'JSESSIONID=SESSION' --data-urlencode 'url=http://localhost:8090/'"},
            {"Cloud metadata", "http://169.254.169.254/latest/meta-data/",
             "AWS/GCP/Azure all serve IAM credentials at this link-local address. One request can leak cloud keys.", "url",
             "curl -s -X POST http://localhost:8090/ssrf/vulnerable -b 'JSESSIONID=SESSION' --data-urlencode 'url=http://169.254.169.254/latest/meta-data/'"},
            {"Internal network scan", "http://192.168.1.1/",
             "The server may sit on an internal network. Use SSRF to reach hosts the attacker cannot access directly.", "url",
             "curl -s -X POST http://localhost:8090/ssrf/vulnerable -b 'JSESSIONID=SESSION' --data-urlencode 'url=http://192.168.1.1/'"},
            {"File read (file://)", "file:///etc/passwd",
             "Some HTTP clients allow file:// URLs. This reads a local file from the server's filesystem.", "url",
             "curl -s -X POST http://localhost:8090/ssrf/vulnerable -b 'JSESSIONID=SESSION' --data-urlencode 'url=file:///etc/passwd'"},
        });

        String content = TemplateEngine.vulnerabilityBadge(Messages.get("ssrf.badge.id"), Messages.get("ssrf.badge.name"), Messages.get("ssrf.badge.tag")) + info + exploits + panels;
        res.getWriter().write(TemplateEngine.page(Messages.get("ssrf.title"), content, true));
    }
}
