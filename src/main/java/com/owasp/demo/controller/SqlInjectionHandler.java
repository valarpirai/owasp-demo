package com.owasp.demo.controller;

import com.owasp.demo.util.Messages;
import com.owasp.demo.model.User;
import com.owasp.demo.repository.UserRepository;
import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.List;

public class SqlInjectionHandler implements IRouteHandler {

    private final UserRepository userRepository = new UserRepository();

    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String path = req.getPathInfo();

        if ("POST".equals(req.getMethod()) && "/sqli/vulnerable".equals(path)) {
            handleVulnerable(req, res);
        } else if ("POST".equals(req.getMethod()) && "/sqli/mitigated".equals(path)) {
            handleMitigated(req, res);
        } else {
            renderPage(res, null, null, null, null);
        }
    }

    private void handleVulnerable(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String input = req.getParameter("username");
        String result;

        try {
            List<User> users = userRepository.findAllUnsafe(input);
            String sql = "SELECT id, username, password, role FROM users WHERE username = '" + input + "'";
            StringBuilder sb = new StringBuilder();
            sb.append("<strong>Executed SQL:</strong> <code class='bg-gray-100 px-1 rounded text-xs'>")
              .append(TemplateEngine.escape(sql))
              .append("</code><br/><br/><strong>Results:</strong><br/>");
            if (users.isEmpty()) {
                sb.append("No results.");
            } else {
                for (User u : users) {
                    sb.append("id=").append(u.id())
                      .append(", username=").append(TemplateEngine.escape(u.username()))
                      .append(", role=").append(TemplateEngine.escape(u.role()))
                      .append("<br/>");
                }
            }
            result = sb.toString();
        } catch (Exception e) {
            result = "Error: " + TemplateEngine.escape(e.getMessage());
        }

        renderPage(res, input, result, null, null);
    }

    private void handleMitigated(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String input = req.getParameter("username2");
        String result;

        try {
            List<User> users = userRepository.findByUsernameSafe(input);
            StringBuilder sb = new StringBuilder();
            sb.append("<strong>Executed SQL:</strong> <code class='bg-gray-100 px-1 rounded text-xs'>")
              .append("SELECT ... FROM users WHERE username = ?")
              .append("</code> param: <code class='bg-gray-100 px-1 rounded text-xs'>")
              .append(TemplateEngine.escape(input))
              .append("</code><br/><br/><strong>Results:</strong><br/>");
            if (users.isEmpty()) {
                sb.append("No results.");
            } else {
                for (User u : users) {
                    sb.append("id=").append(u.id())
                      .append(", username=").append(TemplateEngine.escape(u.username()))
                      .append(", role=").append(TemplateEngine.escape(u.role()))
                      .append("<br/>");
                }
            }
            result = sb.toString();
        } catch (Exception e) {
            result = "Error: " + TemplateEngine.escape(e.getMessage());
        }

        renderPage(res, null, null, input, result);
    }

    private void renderPage(HttpServletResponse res,
                            String vulnInput, String vulnResult,
                            String safeInput, String safeResult) throws IOException {
        String info = TemplateEngine.infoBox(
            Messages.get("sqli.info.explanation"),
            Messages.get("sqli.info.mitigation")
        );

        String exploits = TemplateEngine.exploitBox(new String[][]{
            {"Dump all users", "' OR '1'='1",
             "The WHERE clause becomes always-true. Returns every row in the table.", "username",
             "curl -s -X POST http://localhost:8090/sqli/vulnerable -b 'SESSION_COOKIE=SESSION' --data-urlencode \"username=' OR '1'='1\""},
            {"Login bypass", "admin'--",
             "The -- comment strips the password check. Logs in as admin with no password.", "username",
             "curl -s -X POST http://localhost:8090/sqli/vulnerable -b 'SESSION_COOKIE=SESSION' --data-urlencode \"username=admin'--\""},
            {"UNION extraction", "' UNION SELECT id, username, password, role FROM users--",
             "Appends a second SELECT. Returns usernames and plaintext passwords.", "username",
             "curl -s -X POST http://localhost:8090/sqli/vulnerable -b 'SESSION_COOKIE=SESSION' --data-urlencode \"username=' UNION SELECT id,username,password,role FROM users--\""},
            {"Error-based enumeration", "' AND 1=CONVERT(int,(SELECT TOP 1 password FROM users))--",
             "Forces the DB to cast a string to int, leaking the value in the error message.", "username",
             "curl -s -X POST http://localhost:8090/sqli/vulnerable -b 'SESSION_COOKIE=SESSION' --data-urlencode \"username=' AND 1=CONVERT(int,(SELECT TOP 1 password FROM users))--\""},
        });

        String vulnForm = """
            <form method="POST" action="/sqli/vulnerable" class="space-y-3">
              <label class="block text-sm font-medium text-gray-700">Search username</label>
              <input type="text" name="username" placeholder="e.g. admin' OR '1'='1"
                value="%s"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"/>
              <button class="bg-red-600 text-white px-4 py-2 rounded text-sm hover:bg-red-700">Run Vulnerable Query</button>
            </form>
            """.formatted(TemplateEngine.escape(vulnInput != null ? vulnInput : ""));

        String safeForm = """
            <form method="POST" action="/sqli/mitigated" class="space-y-3">
              <label class="block text-sm font-medium text-gray-700">Search username</label>
              <input type="text" name="username2" placeholder="e.g. admin' OR '1'='1"
                value="%s"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"/>
              <button class="bg-green-600 text-white px-4 py-2 rounded text-sm hover:bg-green-700">Run Safe Query</button>
            </form>
            """.formatted(TemplateEngine.escape(safeInput != null ? safeInput : ""));

        String panels = """
            <div class="grid md:grid-cols-2 gap-6">%s%s</div>
            """.formatted(
                TemplateEngine.demoPanel(Messages.get("sqli.panel.vulnerable"), "red", vulnForm,
                    vulnResult != null ? TemplateEngine.resultBox(vulnResult, false) : ""),
                TemplateEngine.demoPanel(Messages.get("sqli.panel.mitigated"), "green", safeForm,
                    safeResult != null ? TemplateEngine.resultBox(safeResult, true) : "")
            );

        String content = TemplateEngine.vulnerabilityBadge(Messages.get("sqli.badge.id"), Messages.get("sqli.badge.name"), Messages.get("sqli.badge.tag")) + info + exploits + panels;
        res.getWriter().write(TemplateEngine.page(Messages.get("sqli.title"), content, true));
    }
}
