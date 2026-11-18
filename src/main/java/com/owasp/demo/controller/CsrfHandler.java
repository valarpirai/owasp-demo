package com.owasp.demo.controller;

import com.owasp.demo.util.Messages;
import com.owasp.demo.config.AppConfig;
import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.util.Map;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Demonstrates Cross-Site Request Forgery on a "change email" action.
 * The vulnerable endpoint trusts the session cookie alone. The mitigated
 * endpoint also requires a per-session token that a forged request cannot know.
 */
public class CsrfHandler implements IRouteHandler {

    private static final String DEFAULT_EMAIL = AppConfig.get().getString("csrf.default_email");
    private static final String ATTACKER_EMAIL = AppConfig.get().getString("csrf.attacker_email");
    private static final String EMAIL_VULN = "csrfEmailVulnerable";
    private static final String EMAIL_SAFE = "csrfEmailMitigated";
    private static final String TOKEN = "csrfToken";

    private final SecureRandom random = new SecureRandom();

    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String path = req.getPathInfo();
        boolean post = "POST".equals(req.getMethod());

        if (post && "/csrf/vulnerable".equals(path)) {
            handleVulnerable(req, res);
        } else if (post && "/csrf/mitigated".equals(path)) {
            handleMitigated(req, res);
        } else if ("/csrf/attack".equals(path)) {
            renderAttackPage(req, res);
        } else {
            renderPage(req, res, null, null);
        }
    }

    private void handleVulnerable(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String email = req.getParameter("email");
        req.getSession().setAttribute(EMAIL_VULN, email);
        renderPage(req, res, TemplateEngine.resultBox("Email changed to <strong>"
            + TemplateEngine.escape(email) + "</strong>. No token was checked.", false), null);
    }

    private void handleMitigated(HttpServletRequest req, HttpServletResponse res) throws IOException {
        HttpSession session = req.getSession();
        if (!tokenMatches((String) session.getAttribute(TOKEN), req.getParameter("csrfToken"))) {
            res.setStatus(403);
            renderPage(req, res, null, TemplateEngine.resultBox(
                "Rejected. The request carried no valid CSRF token.", false));
            return;
        }
        String email = req.getParameter("email");
        session.setAttribute(EMAIL_SAFE, email);
        renderPage(req, res, null, TemplateEngine.resultBox("Email changed to <strong>"
            + TemplateEngine.escape(email) + "</strong>. The token was valid.", true));
    }

    /**
     * Compares two tokens in constant time.
     *
     * @param expected the token stored in the session
     * @param actual the token sent with the request
     * @return true when both are present and equal
     */
    private boolean tokenMatches(String expected, String actual) {
        if (expected == null || actual == null) return false;
        return MessageDigest.isEqual(
            expected.getBytes(StandardCharsets.UTF_8),
            actual.getBytes(StandardCharsets.UTF_8));
    }

    private String tokenFor(HttpSession session) {
        String token = (String) session.getAttribute(TOKEN);
        if (token == null) {
            byte[] bytes = new byte[32];
            random.nextBytes(bytes);
            token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
            session.setAttribute(TOKEN, token);
        }
        return token;
    }

    private String emailOf(HttpSession session, String key) {
        String email = (String) session.getAttribute(key);
        return email != null ? email : DEFAULT_EMAIL;
    }

    private void renderPage(HttpServletRequest req, HttpServletResponse res,
                            String vulnResult, String safeResult) throws IOException {
        HttpSession session = req.getSession();

        String info = TemplateEngine.infoBox(
            Messages.get("csrf.info.explanation"),
            Messages.get("csrf.info.mitigation")
        );

        String vulnForm = TemplateEngine.render("forms/csrf-vulnerable.html", Map.of(
            "email", TemplateEngine.escape(emailOf(session, EMAIL_VULN)),
            "value", TemplateEngine.escape(emailOf(session, EMAIL_VULN))
        ));

        String safeForm = TemplateEngine.render("forms/csrf-mitigated.html", Map.of(
            "email", TemplateEngine.escape(emailOf(session, EMAIL_SAFE)),
            "token", TemplateEngine.escape(tokenFor(session)),
            "value", TemplateEngine.escape(emailOf(session, EMAIL_SAFE))
        ));

        String panels = """
            <div class="grid md:grid-cols-2 gap-6">
              %s
              %s
            </div>
            """.formatted(
                TemplateEngine.demoPanel(Messages.get("csrf.panel.vulnerable"), "red", vulnForm, vulnResult != null ? vulnResult : ""),
                TemplateEngine.demoPanel(Messages.get("csrf.panel.mitigated"), "green", safeForm, safeResult != null ? safeResult : ""));

        String exploits = TemplateEngine.exploitBox(new String[][]{
            {"Forged form post", "<form action=\"http://localhost:8090/csrf/vulnerable\" method=\"POST\"><input name=\"email\" value=\"" + ATTACKER_EMAIL + "\"></form><script>document.forms[0].submit()</script>",
             "Hosted on any site. Auto-submits as soon as a logged-in victim opens it.", null,
             "curl -s -X POST http://localhost:8090/csrf/vulnerable -b 'SESSION_COOKIE=SESSION' --data-urlencode 'email=" + ATTACKER_EMAIL + "'"},
            {"Same request, no token", "POST /csrf/mitigated  email=" + ATTACKER_EMAIL,
             "The forged request has the cookie but not the token. The server answers 403.", null,
             "curl -s -X POST http://localhost:8090/csrf/mitigated -b 'SESSION_COOKIE=SESSION' --data-urlencode 'email=" + ATTACKER_EMAIL + "'"},
        });

        String content = TemplateEngine.vulnerabilityBadge(Messages.get("csrf.badge.id"), Messages.get("csrf.badge.name"), Messages.get("csrf.badge.tag"))
            + info + exploits + panels;
        res.getWriter().write(TemplateEngine.page(Messages.get("csrf.title"), content, true));
    }

    /**
     * Renders the attacker's page. It posts a forged email change without a token.
     * Only the two known targets are accepted, so the form action is never user-controlled.
     */
    private void renderAttackPage(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String target = "mitigated".equals(req.getParameter("target")) ? "mitigated" : "vulnerable";
        res.getWriter().write("""
            <!doctype html>
            <html><head><title>You won a prize!</title></head>
            <body style="font-family:sans-serif;text-align:center;margin-top:4rem">
              <h1>🎁 Claiming your prize...</h1>
              <p>This page is the attacker's. It silently posts a form to <code>/csrf/%s</code>.</p>
              <form action="/csrf/%s" method="POST">
                <input type="hidden" name="email" value="%s"/>
                <noscript><button>Claim prize</button></noscript>
              </form>
              <script>document.forms[0].submit()</script>
            </body></html>
            """.formatted(target, target, ATTACKER_EMAIL));
    }
}
