package com.owasp.demo.controller;

import com.owasp.demo.util.Messages;
import com.owasp.demo.model.User;
import com.owasp.demo.repository.UserRepository;
import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.util.List;

public class BrokenAccessHandler implements IRouteHandler {

    private final UserRepository userRepository = new UserRepository();

    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String path = req.getPathInfo();

        if ("/bac/vulnerable".equals(path)) {
            handleVulnerable(req, res);
        } else if ("/bac/mitigated".equals(path)) {
            handleMitigated(req, res);
        } else {
            renderPage(res, null, null);
        }
    }

    private void handleVulnerable(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String result;
        try {
            List<User> users = userRepository.findAll();
            StringBuilder sb = new StringBuilder();
            sb.append("<table class='w-full text-sm border-collapse'>");
            sb.append("<tr class='bg-gray-100'><th class='border px-2 py-1'>ID</th><th class='border px-2 py-1'>Username</th><th class='border px-2 py-1 text-red-600'>Password</th><th class='border px-2 py-1'>Role</th></tr>");
            for (User u : users) {
                sb.append("<tr>")
                  .append("<td class='border px-2 py-1'>").append(u.id()).append("</td>")
                  .append("<td class='border px-2 py-1'>").append(TemplateEngine.escape(u.username())).append("</td>")
                  .append("<td class='border px-2 py-1 text-red-600'>").append(TemplateEngine.escape(u.password())).append("</td>")
                  .append("<td class='border px-2 py-1'>").append(TemplateEngine.escape(u.role())).append("</td>")
                  .append("</tr>");
            }
            sb.append("</table>");
            result = sb.toString();
        } catch (Exception e) {
            result = "Error: " + TemplateEngine.escape(e.getMessage());
        }
        renderPage(res, result, null);
    }

    private void handleMitigated(HttpServletRequest req, HttpServletResponse res) throws IOException {
        HttpSession session = req.getSession(false);
        String role = session != null ? (String) session.getAttribute("role") : null;

        if (!"ADMIN".equals(role)) {
            renderPage(res, null,
                "<span class='text-red-600 font-semibold'>403 Forbidden — Admin role required. " +
                "Your role: " + TemplateEngine.escape(role) + "</span>");
            return;
        }

        String result;
        try {
            List<User> users = userRepository.findAll();
            StringBuilder sb = new StringBuilder();
            sb.append("<table class='w-full text-sm border-collapse'>");
            sb.append("<tr class='bg-gray-100'><th class='border px-2 py-1'>ID</th><th class='border px-2 py-1'>Username</th><th class='border px-2 py-1'>Role</th></tr>");
            for (User u : users) {
                sb.append("<tr>")
                  .append("<td class='border px-2 py-1'>").append(u.id()).append("</td>")
                  .append("<td class='border px-2 py-1'>").append(TemplateEngine.escape(u.username())).append("</td>")
                  .append("<td class='border px-2 py-1'>").append(TemplateEngine.escape(u.role())).append("</td>")
                  .append("</tr>");
            }
            sb.append("</table>");
            result = sb.toString();
        } catch (Exception e) {
            result = "Error: " + TemplateEngine.escape(e.getMessage());
        }
        renderPage(res, null, result);
    }

    private void renderPage(HttpServletResponse res, String vulnResult, String safeResult) throws IOException {
        String info = TemplateEngine.infoBox(
            Messages.get("bac.info.explanation"),
            Messages.get("bac.info.mitigation")
        );

        String vulnBtn = """
            <a href="/bac/vulnerable"
               class="inline-block bg-red-600 text-white px-4 py-2 rounded text-sm hover:bg-red-700">
              Fetch Admin Data (No Role Check)
            </a>
            %s
            """.formatted(vulnResult != null ? "<div class='mt-3'>" + vulnResult + "</div>" : "");

        String safeBtn = """
            <a href="/bac/mitigated"
               class="inline-block bg-green-600 text-white px-4 py-2 rounded text-sm hover:bg-green-700">
              Fetch Admin Data (Role Check)
            </a>
            <p class="text-xs text-gray-500 mt-1">Logged in as admin → access granted. Log in as 'user' to see the 403.</p>
            %s
            """.formatted(safeResult != null ? "<div class='mt-3'>" + safeResult + "</div>" : "");

        String panels = """
            <div class="grid md:grid-cols-2 gap-6">%s%s</div>
            """.formatted(
                TemplateEngine.demoPanel(Messages.get("bac.panel.vulnerable"), "red", vulnBtn, ""),
                TemplateEngine.demoPanel(Messages.get("bac.panel.mitigated"), "green", safeBtn, "")
            );

        String exploits = TemplateEngine.exploitBox(new String[][]{
            {"Direct object access", "GET /bac/vulnerable",
             "Visit this URL as any logged-in user (even role=USER) to dump all user records including passwords.",
             null,
             "curl -s http://localhost:8090/bac/vulnerable -b 'JSESSIONID=SESSION'"},
            {"IDOR — change user ID", "GET /bac/vulnerable?id=1",
             "Predictable IDs let an attacker enumerate records by incrementing the id parameter.",
             null,
             "curl -s 'http://localhost:8090/bac/vulnerable?id=1' -b 'JSESSIONID=SESSION'"},
            {"Role parameter tampering", "POST /bac/mitigated  body: role=ADMIN",
             "Sending a forged role in the request body bypasses client-enforced role checks.",
             null,
             "curl -s -X POST http://localhost:8090/bac/mitigated -b 'JSESSIONID=SESSION' -d 'role=ADMIN'"},
        });

        String content = TemplateEngine.vulnerabilityBadge(Messages.get("bac.badge.id"), Messages.get("bac.badge.name"), Messages.get("bac.badge.tag")) + info + exploits + panels;
        res.getWriter().write(TemplateEngine.page(Messages.get("bac.title"), content, true));
    }
}
