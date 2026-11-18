package com.owasp.demo.controller;

import com.owasp.demo.util.Messages;
import com.owasp.demo.config.AppConfig;
import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

@Controller
public class InsecureDesignHandler {

    private static final String CORRECT_OTP = AppConfig.get().getString("otp.correct_code");

    @GetMapping("/insecure-design")
    public void page(HttpServletRequest req, HttpServletResponse res) throws IOException {
        renderPage(res, null, null);
    }

    @PostMapping("/insecure-design/vulnerable")
    private void handleVulnerable(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String otp = req.getParameter("otp");
        String result = CORRECT_OTP.equals(otp)
            ? "<span class='text-green-700 font-semibold'>OTP accepted! Access granted.</span>"
            : "<span class='text-red-600'>Wrong OTP. Try again — no limit on attempts!</span>";
        renderPage(res, result, null);
    }

    @PostMapping("/insecure-design/mitigated")
    private void handleMitigated(HttpServletRequest req, HttpServletResponse res) throws IOException {
        HttpSession session = req.getSession(true);
        AtomicInteger counter = (AtomicInteger) session.getAttribute("otp_attempts");
        if (counter == null) {
            counter = new AtomicInteger(0);
            session.setAttribute("otp_attempts", counter);
        }

        int maxAttempts = AppConfig.get().getOtpMaxAttempts();
        if (counter.get() >= maxAttempts) {
            renderPage(res, null,
                "<span class='text-red-600 font-semibold'>Account locked after " + maxAttempts +
                " failed attempts. Try again later.</span>");
            return;
        }

        String otp = req.getParameter("otp2");
        if (CORRECT_OTP.equals(otp)) {
            session.removeAttribute("otp_attempts");
            renderPage(res, null, "<span class='text-green-700 font-semibold'>OTP accepted! Access granted.</span>");
        } else {
            int attempts = counter.incrementAndGet();
            int remaining = maxAttempts - attempts;
            renderPage(res, null,
                "<span class='text-red-600'>Wrong OTP. " + remaining + " attempt(s) remaining.</span>");
        }
    }

    private void renderPage(HttpServletResponse res, String vulnResult, String safeResult) throws IOException {
        String info = TemplateEngine.infoBox(
            Messages.get("insecure-design.info.explanation"),
            Messages.get("insecure-design.info.mitigation")
        );

        String hint = "<p class='text-xs text-gray-500 mt-2'>Hint: the OTP is <code>123456</code>. " +
                      "In the vulnerable panel you can submit unlimited wrong guesses first.</p>";

        String vulnForm = TemplateEngine.render("forms/insecure-design-vulnerable.html", Map.of(
            "hint", hint
        ));

        String safeForm = TemplateEngine.render("forms/insecure-design-mitigated.html", Map.of(
            "hint", hint
        ));

        String panels = """
            <div class="grid md:grid-cols-2 gap-6">%s%s</div>
            """.formatted(
                TemplateEngine.demoPanel(Messages.get("insecure-design.panel.vulnerable"), "red", vulnForm,
                    vulnResult != null ? TemplateEngine.resultBox(vulnResult, false) : ""),
                TemplateEngine.demoPanel(Messages.get("insecure-design.panel.mitigated"), "green", safeForm,
                    safeResult != null ? TemplateEngine.resultBox(safeResult, true) : "")
            );

        String exploits = TemplateEngine.exploitBox(new String[][]{
            {"Brute-force correct OTP", "123456",
             "This is the hardcoded correct value. In the vulnerable panel you can guess it after any number of wrong attempts.", "otp",
             "curl -s -X POST http://localhost:8090/insecure-design/vulnerable -b 'SESSION_COOKIE=SESSION' -d 'otp=123456'"},
            {"Sequential guessing", "000000",
             "Script 000000 through 999999 — only 1 million combinations. No rate limit means this completes in seconds.", "otp",
             "for i in $(seq -w 0 999999); do curl -s -X POST http://localhost:8090/insecure-design/vulnerable -b 'SESSION_COOKIE=SESSION' -d \"otp=$i\" | grep -q 'accepted' && echo \"Found: $i\" && break; done"},
            {"Common OTP", "111111",
             "Users often set PINs like 111111 or 123456. Try predictable codes first before brute-forcing.", "otp",
             "curl -s -X POST http://localhost:8090/insecure-design/vulnerable -b 'SESSION_COOKIE=SESSION' -d 'otp=111111'"},
        });

        String content = TemplateEngine.vulnerabilityBadge(Messages.get("insecure-design.badge.id"), Messages.get("insecure-design.badge.name"), Messages.get("insecure-design.badge.tag")) + info + exploits + panels;
        res.getWriter().write(TemplateEngine.page(Messages.get("insecure-design.title"), content, true));
    }
}
