package com.owasp.demo.controller;

import com.owasp.demo.util.Messages;
import com.owasp.demo.config.AppConfig;
import com.owasp.demo.model.User;
import com.owasp.demo.repository.UserRepository;
import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

@Controller
public class AuthFailuresHandler {

    private final UserRepository userRepository = new UserRepository();

    @GetMapping("/auth-failures")
    public void page(HttpServletRequest req, HttpServletResponse res) throws IOException {
        renderPage(res, null, null);
    }

    @PostMapping("/auth-failures/vulnerable")
    private void handleVulnerable(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String username = req.getParameter("username");
        String password = req.getParameter("password");
        String result;

        try {
            Optional<User> user = userRepository.findByUsernameAndPasswordSafe(username, password);
            if (user.isPresent()) {
                String weakToken = username + "_" + System.currentTimeMillis();
                result = "<span class='text-green-700'>Login OK. Session token: <code class='text-xs'>" +
                         TemplateEngine.escape(weakToken) + "</code></span><br/>" +
                         "<span class='text-red-600 text-xs'>Token is predictable — based on username + timestamp.</span>";
            } else {
                result = "<span class='text-red-600'>Invalid credentials. No lockout — try again unlimited times.</span>";
            }
        } catch (Exception e) {
            result = "Error: " + TemplateEngine.escape(e.getMessage());
        }
        renderPage(res, result, null);
    }

    @PostMapping("/auth-failures/mitigated")
    private void handleMitigated(HttpServletRequest req, HttpServletResponse res) throws IOException {
        HttpSession session = req.getSession(true);
        AtomicInteger fails = (AtomicInteger) session.getAttribute("auth_fails");
        if (fails == null) {
            fails = new AtomicInteger(0);
            session.setAttribute("auth_fails", fails);
        }

        int maxAttempts = AppConfig.get().getMaxFailedAttempts();
        if (fails.get() >= maxAttempts) {
            renderPage(res, null,
                "<span class='text-red-600 font-semibold'>Account locked after " + maxAttempts +
                " failed attempts. Please wait " + AppConfig.get().getLockoutMinutes() + " min.</span>");
            return;
        }

        String username = req.getParameter("username2");
        String password = req.getParameter("password2");
        String result;

        try {
            Optional<User> user = userRepository.findByUsernameAndPasswordSafe(username, password);
            if (user.isPresent()) {
                session.removeAttribute("auth_fails");
                String secureToken = UUID.randomUUID().toString();
                result = "<span class='text-green-700'>Login OK. Session token: <code class='text-xs'>" +
                         secureToken + "</code></span><br/>" +
                         "<span class='text-green-600 text-xs'>Token is a cryptographically random UUID — not guessable.</span>";
            } else {
                int remaining = maxAttempts - fails.incrementAndGet();
                result = "<span class='text-red-600'>Invalid credentials. " + remaining + " attempt(s) left.</span>";
            }
        } catch (Exception e) {
            result = "Error: " + TemplateEngine.escape(e.getMessage());
        }
        renderPage(res, null, result);
    }

    private void renderPage(HttpServletResponse res, String vulnResult, String safeResult) throws IOException {
        String info = TemplateEngine.infoBox(
            Messages.get("auth-failures.info.explanation"),
            Messages.get("auth-failures.info.mitigation")
        );

        String vulnForm = TemplateEngine.load("forms/auth-failures-vulnerable.html");

        String safeForm = TemplateEngine.load("forms/auth-failures-mitigated.html");

        String panels = """
            <div class="grid md:grid-cols-2 gap-6">%s%s</div>
            """.formatted(
                TemplateEngine.demoPanel(Messages.get("auth-failures.panel.vulnerable"), "red", vulnForm,
                    vulnResult != null ? TemplateEngine.resultBox(vulnResult, false) : ""),
                TemplateEngine.demoPanel(Messages.get("auth-failures.panel.mitigated"), "green", safeForm,
                    safeResult != null ? TemplateEngine.resultBox(safeResult, true) : "")
            );

        String exploits = TemplateEngine.exploitBox(new String[][]{
            {"Credential stuffing", "admin / admin123",
             "Try the seeded default credentials — no lockout means an attacker can test millions of leaked credential pairs.", "username",
             "curl -s -X POST http://localhost:8090/auth-failures/vulnerable -b 'SESSION_COOKIE=SESSION' -d 'username=admin&password=admin123'"},
            {"Weak password spray", "user / password",
             "Spray one common password across all usernames. Without lockout this runs silently.", "username",
             "for u in admin user guest root; do curl -s -X POST http://localhost:8090/auth-failures/vulnerable -b 'SESSION_COOKIE=SESSION' -d \"username=$u&password=password\" | grep -o 'Login OK\\|Invalid'; done"},
            {"Token prediction", "admin_1700000000000",
             "The vulnerable token is username + System.currentTimeMillis(). Guess the timestamp window to forge it.",
             null,
             "curl -s -X POST http://localhost:8090/auth-failures/vulnerable -b 'SESSION_COOKIE=SESSION' -d 'username=admin&password=admin123' | grep -o 'token.*</code>'"},
        });

        String content = TemplateEngine.vulnerabilityBadge(Messages.get("auth-failures.badge.id"), Messages.get("auth-failures.badge.name"), Messages.get("auth-failures.badge.tag")) + info + exploits + panels;
        res.getWriter().write(TemplateEngine.page(Messages.get("auth-failures.title"), content, true));
    }
}
