package com.owasp.demo.controller;

import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

public class CryptoFailuresHandler implements IRouteHandler {

    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String path = req.getPathInfo();

        if ("POST".equals(req.getMethod()) && "/crypto/vulnerable".equals(path)) {
            handleVulnerable(req, res);
        } else if ("POST".equals(req.getMethod()) && "/crypto/mitigated".equals(path)) {
            handleMitigated(req, res);
        } else {
            renderPage(res, null, null, null, null);
        }
    }

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
            "Passwords are hashed with MD5, a fast, broken algorithm. Precomputed rainbow tables " +
            "can crack most MD5-hashed passwords in seconds. No salt means identical passwords " +
            "produce identical hashes, enabling bulk cracking.",
            "Use a slow, salted algorithm designed for passwords: bcrypt, scrypt, or Argon2. " +
            "Never use MD5/SHA-1/SHA-256 directly for password storage. Store the salt alongside " +
            "the hash and always use a unique random salt per user."
        );

        String vulnForm = """
            <form method="POST" action="/crypto/vulnerable" class="space-y-3">
              <label class="block text-sm font-medium text-gray-700">Enter a password to hash</label>
              <input type="text" name="password" placeholder="e.g. hunter2"
                value="%s"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"/>
              <button class="bg-red-600 text-white px-4 py-2 rounded text-sm hover:bg-red-700">Hash with MD5</button>
            </form>
            """.formatted(TemplateEngine.escape(vulnInput != null ? vulnInput : ""));

        String safeForm = """
            <form method="POST" action="/crypto/mitigated" class="space-y-3">
              <label class="block text-sm font-medium text-gray-700">Enter a password to hash</label>
              <input type="text" name="password2" placeholder="e.g. hunter2"
                value="%s"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"/>
              <button class="bg-green-600 text-white px-4 py-2 rounded text-sm hover:bg-green-700">Hash with Salt + SHA-256</button>
            </form>
            """.formatted(TemplateEngine.escape(safeInput != null ? safeInput : ""));

        String panels = """
            <div class="grid md:grid-cols-2 gap-6">
              %s
              %s
            </div>
            """.formatted(
                TemplateEngine.demoPanel("Vulnerable — MD5, No Salt", "red", vulnForm,
                    vulnResult != null ? TemplateEngine.resultBox(vulnResult, false) : ""),
                TemplateEngine.demoPanel("Mitigated — Salted SHA-256", "green", safeForm,
                    safeResult != null ? TemplateEngine.resultBox(safeResult, true) : "")
            );

        String exploits = TemplateEngine.exploitBox(new String[][]{
            {"Common password", "password123",
             "Hash it here then search CrackStation.net — the MD5 result reverses instantly from rainbow tables.", "password",
             "curl -s -X POST http://localhost:8090/crypto/vulnerable -b 'JSESSIONID=SESSION' -d 'password=password123'"},
            {"Admin password", "admin123",
             "This app's seed password. Its MD5 hash (0192023a7bbd73250516f069df18b500) is in every rainbow table.", "password",
             "curl -s -X POST http://localhost:8090/crypto/vulnerable -b 'JSESSIONID=SESSION' -d 'password=admin123'"},
            {"Empty password", "",
             "MD5 of an empty string (d41d8cd98f00b204e9800998ecf8427e) is well-known. bcrypt handles this safely.", "password",
             "curl -s -X POST http://localhost:8090/crypto/vulnerable -b 'JSESSIONID=SESSION' -d 'password='"},
        });

        String content = TemplateEngine.vulnerabilityBadge("A02", "Cryptographic Failures", "Crypto") + info + exploits + panels;
        res.getWriter().write(TemplateEngine.page("Cryptographic Failures", content, true));
    }
}
