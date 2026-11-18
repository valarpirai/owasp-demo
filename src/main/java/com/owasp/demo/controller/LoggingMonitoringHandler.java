package com.owasp.demo.controller;

import com.owasp.demo.util.Messages;
import com.owasp.demo.model.AuditLog;
import com.owasp.demo.model.User;
import com.owasp.demo.repository.AuditLogRepository;
import com.owasp.demo.repository.UserRepository;
import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Map;
import java.util.List;
import java.util.Optional;

@Controller
public class LoggingMonitoringHandler {

    private final UserRepository userRepository = new UserRepository();
    private final AuditLogRepository auditLogRepository = new AuditLogRepository();

    @GetMapping("/logging")
    public void page(HttpServletRequest req, HttpServletResponse res) throws IOException {
        renderPage(res, null, null);
    }

    @PostMapping("/logging/vulnerable")
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

    @PostMapping("/logging/mitigated")
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
            Messages.get("logging.info.explanation"),
            Messages.get("logging.info.mitigation")
        );

        String vulnForm = TemplateEngine.load("forms/logging-vulnerable.html");

        String safeForm = TemplateEngine.load("forms/logging-mitigated.html");

        String auditTable = buildAuditTable();

        String panels = """
            <div class="grid md:grid-cols-2 gap-6">%s%s</div>
            <div class="mt-6">
              <h3 class="font-semibold text-gray-700 mb-2">Audit Log (last 10 entries)</h3>
              %s
            </div>
            """.formatted(
                TemplateEngine.demoPanel(Messages.get("logging.panel.vulnerable"), "red", vulnForm,
                    vulnResult != null ? TemplateEngine.resultBox(vulnResult, false) : ""),
                TemplateEngine.demoPanel(Messages.get("logging.panel.mitigated"), "green", safeForm,
                    safeResult != null ? TemplateEngine.resultBox(safeResult, true) : ""),
                auditTable
            );

        String exploits = TemplateEngine.exploitBox(new String[][]{
            {"Silent brute-force", "wrongpassword",
             "Submit wrong passwords repeatedly on the vulnerable panel — nothing is logged, attack is invisible.", "username",
             "for p in password 123456 admin letmein; do curl -s -X POST http://localhost:8090/logging/vulnerable -b 'SESSION_COOKIE=SESSION' -d \"username=admin&password=$p\"; done"},
            {"Valid credentials (no log)", "admin",
             "Even a successful login on the vulnerable side leaves no audit trail to correlate with prior failures.", "username",
             "curl -s -X POST http://localhost:8090/logging/vulnerable -b 'SESSION_COOKIE=SESSION' -d 'username=admin&password=admin123'"},
            {"Log injection attempt", "admin\nLOGIN_SUCCESS user=attacker",
             "Some loggers write raw input. Newline injection can forge log entries to cover tracks.", "username",
             "curl -s -X POST http://localhost:8090/logging/vulnerable -b 'SESSION_COOKIE=SESSION' --data-urlencode $'username=admin\\nLOGIN_SUCCESS user=attacker' -d 'password=x'"},
        });

        String content = TemplateEngine.vulnerabilityBadge(Messages.get("logging.badge.id"), Messages.get("logging.badge.name"), Messages.get("logging.badge.tag")) + info + exploits + panels;
        res.getWriter().write(TemplateEngine.page(Messages.get("logging.title"), content, true));
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
