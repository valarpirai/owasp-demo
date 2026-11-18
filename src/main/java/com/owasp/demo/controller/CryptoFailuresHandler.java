package com.owasp.demo.controller;

import com.owasp.demo.util.Messages;
import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Map;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

@Controller
public class CryptoFailuresHandler {

    @GetMapping("/crypto")
    public void page(HttpServletRequest req, HttpServletResponse res) throws IOException {
        renderPage(res, null, null, null, null);
    }

    @PostMapping("/crypto/vulnerable")
    private void handleVulnerable(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String password = req.getParameter("password");
        String result;
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
            String md5 = HexFormat.of().formatHex(hash);
            result = "Password: <code>" + TemplateEngine.escape(password) + "</code><br/>" +
                     "MD5 hash stored: <code class='text-red-600'>" + md5 + "</code><br/>" +
                     "<span class='text-red-600 text-xs'>MD5 is broken — rainbow tables can reverse this instantly.</span>";
        } catch (Exception e) {
            result = "Error: " + TemplateEngine.escape(e.getMessage());
        }
        renderPage(res, password, result, null, null);
    }

    @PostMapping("/crypto/mitigated")
    private void handleMitigated(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String password = req.getParameter("password2");
        String result;
        try {
            SecureRandom rng = new SecureRandom();
            byte[] saltBytes = new byte[16];
            rng.nextBytes(saltBytes);
            String salt = Base64.getEncoder().encodeToString(saltBytes);

            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(saltBytes);
            byte[] hash = sha.digest(password.getBytes(StandardCharsets.UTF_8));
            String encoded = Base64.getEncoder().encodeToString(hash);

            result = "Password: <code>" + TemplateEngine.escape(password) + "</code><br/>" +
                     "Salt (random, per user): <code class='text-green-700'>" + salt + "</code><br/>" +
                     "SHA-256(salt + password): <code class='text-green-700'>" + encoded + "</code><br/>" +
                     "<span class='text-green-600 text-xs'>In production use bcrypt/Argon2 for proper work-factor tuning.</span>";
        } catch (Exception e) {
            result = "Error: " + TemplateEngine.escape(e.getMessage());
        }
        renderPage(res, null, null, password, result);
    }

    private void renderPage(HttpServletResponse res,
                            String vulnInput, String vulnResult,
                            String safeInput, String safeResult) throws IOException {
        String info = TemplateEngine.infoBox(
            Messages.get("crypto.info.explanation"),
            Messages.get("crypto.info.mitigation")
        );

        String vulnForm = TemplateEngine.render("forms/crypto-vulnerable.html", Map.of(
            "value", TemplateEngine.escape(vulnInput != null ? vulnInput : "")
        ));

        String safeForm = TemplateEngine.render("forms/crypto-mitigated.html", Map.of(
            "value", TemplateEngine.escape(safeInput != null ? safeInput : "")
        ));

        String panels = """
            <div class="grid md:grid-cols-2 gap-6">
              %s
              %s
            </div>
            """.formatted(
                TemplateEngine.demoPanel(Messages.get("crypto.panel.vulnerable"), "red", vulnForm,
                    vulnResult != null ? TemplateEngine.resultBox(vulnResult, false) : ""),
                TemplateEngine.demoPanel(Messages.get("crypto.panel.mitigated"), "green", safeForm,
                    safeResult != null ? TemplateEngine.resultBox(safeResult, true) : "")
            );

        String exploits = TemplateEngine.exploitBox(new String[][]{
            {"Common password", "password123",
             "Hash it here then search CrackStation.net — the MD5 result reverses instantly from rainbow tables.", "password",
             "curl -s -X POST http://localhost:8090/crypto/vulnerable -b 'SESSION_COOKIE=SESSION' -d 'password=password123'"},
            {"Admin password", "admin123",
             "This app's seed password. Its MD5 hash (0192023a7bbd73250516f069df18b500) is in every rainbow table.", "password",
             "curl -s -X POST http://localhost:8090/crypto/vulnerable -b 'SESSION_COOKIE=SESSION' -d 'password=admin123'"},
            {"Empty password", "",
             "MD5 of an empty string (d41d8cd98f00b204e9800998ecf8427e) is well-known. bcrypt handles this safely.", "password",
             "curl -s -X POST http://localhost:8090/crypto/vulnerable -b 'SESSION_COOKIE=SESSION' -d 'password='"},
        });

        String content = TemplateEngine.vulnerabilityBadge(Messages.get("crypto.badge.id"), Messages.get("crypto.badge.name"), Messages.get("crypto.badge.tag")) + info + exploits + panels;
        res.getWriter().write(TemplateEngine.page(Messages.get("crypto.title"), content, true));
    }
}
