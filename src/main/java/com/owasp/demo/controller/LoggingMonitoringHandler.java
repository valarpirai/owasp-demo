package com.owasp.demo.controller;

import com.owasp.demo.model.AuditLog;
import com.owasp.demo.model.User;
import com.owasp.demo.repository.AuditLogRepository;
import com.owasp.demo.repository.UserRepository;
import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

public class LoggingMonitoringHandler implements IRouteHandler {

    private final UserRepository userRepository = new UserRepository();
    private final AuditLogRepository auditLogRepository = new AuditLogRepository();

    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String path = req.getServletPath();

        if ("POST".equals(req.getMethod()) && "/logging/vulnerable".equals(path)) {
            handleVulnerable(req, res);
        } else if ("POST".equals(req.getMethod()) && "/logging/mitigated".equals(path)) {
            handleMitigated(req, res);
        } else {
            renderPage(res, null, null);
        }
    }

    private void handleVulnerable(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String username = req.getParameter("username");
        String password = req.getParameter("password");
        String result;

        try {
            Optional<User> user = userRepository.findByUsernameAndPasswordSafe(username, password);
            result = user.isPresent()
                ? "<span class='text-green-700'>Login succeeded (no log written).</span>"
                : "<span class='text-red-600'>Login failed — nothing logged. " +
                  "Attacker can brute-force silently.</span>";
        } catch (Exception e) {
            result = "Error: " + TemplateEngine.escape(e.getMessage());
        }
        renderPage(res, result, null);
    }

    private void handleMitigated(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String username = req.getParameter("username2");
        String password = req.getParameter("password2");
        String result;

        try {
            Optional<User> user = userRepository.findByUsernameAndPasswordSafe(username, password);
            if (user.isPresent()) {
                auditLogRepository.log("LOGIN_SUCCESS", "user=" + username);
                result = "<span class='text-green-700'>Login succeeded — event logged.</span>";
            } else {
                auditLogRepository.log("LOGIN_FAILED", "user=" + username);
                result = "<span class='text-orange-600'>Login failed — event written to audit log.</span>";
            }
        } catch (Exception e) {
            result = "Error: " + TemplateEngine.escape(e.getMessage());
        }
        renderPage(res, null, result);
    }

    private void renderPage(HttpServletResponse res, String vulnResult, String safeResult) throws IOException {
        String info = TemplateEngine.infoBox(
            "Failed login attempts are silently discarded. Without logs, a security team " +
            "cannot detect ongoing brute-force attacks, credential stuffing, or account takeovers " +
            "until it is too late.",
            "Log all authentication events (success and failure) with timestamp, username, and " +
            "source IP. Store logs in a tamper-evident system. Alert on unusual failure rates. " +
            "The audit log table in this demo shows live entries below."
        );

        String vulnForm = """
            <form method="POST" action="/logging/vulnerable" class="space-y-3">
              <input type="text" name="username" placeholder="Username"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"/>
              <input type="password" name="password" placeholder="Password"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"/>
              <button class="bg-red-600 text-white px-4 py-2 rounded text-sm hover:bg-red-700">Login (No Logging)</button>
            </form>
            """;

        String safeForm = """
            <form method="POST" action="/logging/mitigated" class="space-y-3">
              <input type="text" name="username2" placeholder="Username"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"/>
              <input type="password" name="password2" placeholder="Password"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"/>
              <button class="bg-green-600 text-white px-4 py-2 rounded text-sm hover:bg-green-700">Login (Logged)</button>
            </form>
            """;

        String auditTable = buildAuditTable();

        String panels = """
            <div class="grid md:grid-cols-2 gap-6">%s%s</div>
            <div class="mt-6">
              <h3 class="font-semibold text-gray-700 mb-2">Audit Log (last 10 entries)</h3>
              %s
            </div>
            """.formatted(
                TemplateEngine.demoPanel("Vulnerable — Silent Failure", "red", vulnForm,
                    vulnResult != null ? TemplateEngine.resultBox(vulnResult, false) : ""),
                TemplateEngine.demoPanel("Mitigated — Audit Logged", "green", safeForm,
                    safeResult != null ? TemplateEngine.resultBox(safeResult, true) : ""),
                auditTable
            );

        String content = TemplateEngine.vulnerabilityBadge("A09", "Security Logging & Monitoring Failures") + info + panels;
        res.getWriter().write(TemplateEngine.page("Logging Failures", content, true));
    }

    private String buildAuditTable() {
        try {
            List<AuditLog> logs = auditLogRepository.findRecent(10);
            if (logs.isEmpty()) {
                return "<p class='text-sm text-gray-500'>No log entries yet. Use the mitigated panel to generate some.</p>";
            }
            StringBuilder sb = new StringBuilder();
            sb.append("<table class='w-full text-sm bg-white shadow rounded'>");
            sb.append("<thead class='bg-gray-100'><tr><th class='px-3 py-2 text-left'>Time</th><th class='px-3 py-2 text-left'>Event</th><th class='px-3 py-2 text-left'>Details</th></tr></thead><tbody>");
            for (AuditLog log : logs) {
                sb.append("<tr class='border-b'>");
                sb.append("<td class='px-3 py-1 text-xs text-gray-500'>").append(log.eventTime()).append("</td>");
                sb.append("<td class='px-3 py-1'>").append(TemplateEngine.escape(log.event())).append("</td>");
                sb.append("<td class='px-3 py-1 text-xs'>").append(TemplateEngine.escape(log.details())).append("</td>");
                sb.append("</tr>");
            }
            sb.append("</tbody></table>");
            return sb.toString();
        } catch (Exception e) {
            return "<p class='text-red-500 text-sm'>Error loading logs: " + TemplateEngine.escape(e.getMessage()) + "</p>";
        }
    }
}
