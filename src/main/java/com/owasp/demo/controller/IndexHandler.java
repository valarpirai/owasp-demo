package com.owasp.demo.controller;

import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;

public class IndexHandler implements IRouteHandler {

    private record VulnCard(String id, String name, String path, String description) {}

    private static final VulnCard[] CARDS = {
        new VulnCard("A01", "Broken Access Control",       "/bac",             "Restrictions on authenticated users are not properly enforced."),
        new VulnCard("A02", "Cryptographic Failures",      "/crypto",          "Sensitive data exposed due to weak or missing cryptography."),
        new VulnCard("A03", "Injection",                   "/sqli",            "Hostile data is sent to an interpreter as part of a query or command."),
        new VulnCard("A04", "Insecure Design",             "/insecure-design", "Missing or ineffective control design allows abuse of business logic."),
        new VulnCard("A05", "Security Misconfiguration",   "/misconfig",       "Insecure default configs, verbose errors, or unnecessary features enabled."),
        new VulnCard("A06", "Vulnerable Components",       "/vuln-components", "Components with known vulnerabilities used without patching."),
        new VulnCard("A07", "Auth Failures",               "/auth-failures",   "Weaknesses in authentication allow account compromise."),
        new VulnCard("A08", "Data Integrity Failures",     "/integrity",       "Code and data integrity failures, insecure deserialization."),
        new VulnCard("A09", "Logging & Monitoring Failures","/logging",        "Insufficient logging prevents detection of active breaches."),
        new VulnCard("A10", "SSRF",                        "/ssrf",            "Server fetches a remote resource from an attacker-controlled URL."),
        new VulnCard("A03", "OS Command Injection (RCE)", "/rce",             "User input concatenated into a shell command executes arbitrary OS commands."),
        new VulnCard("A01", "Cross-Site Request Forgery", "/csrf",            "A forged request rides on the victim's session cookie to change state.")
    };

    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        HttpSession session = req.getSession(false);
        String user = session != null ? (String) session.getAttribute("user") : "?";

        StringBuilder cards = new StringBuilder();
        for (VulnCard c : CARDS) {
            cards.append("""
                <a href="%s" class="block bg-white rounded-lg shadow hover:shadow-md transition p-5 border-l-4 border-red-500">
                  <div class="flex items-center gap-2 mb-1">
                    <span class="bg-red-100 text-red-700 text-xs font-bold px-2 py-0.5 rounded">%s</span>
                  </div>
                  <h3 class="font-semibold text-gray-800 mb-1">%s</h3>
                  <p class="text-sm text-gray-500">%s</p>
                </a>
                """.formatted(c.path(), c.id(), c.name(), c.description()));
        }

        String content = """
            <div class="mb-8">
              <h1 class="text-3xl font-bold text-gray-800">OWASP Top 10 Vulnerability Demo</h1>
              <p class="text-gray-500 mt-1">Logged in as <strong>%s</strong>. Select a vulnerability to explore.</p>
            </div>
            <div class="grid sm:grid-cols-2 gap-4">
              %s
            </div>
            """.formatted(TemplateEngine.escape(user), cards);

        res.getWriter().write(TemplateEngine.page("Dashboard", content, true));
    }
}
