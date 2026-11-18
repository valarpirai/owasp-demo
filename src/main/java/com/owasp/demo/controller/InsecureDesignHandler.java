package com.owasp.demo.controller;

import com.owasp.demo.config.AppConfig;
import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;

public class InsecureDesignHandler implements IRouteHandler {

    private static final String CORRECT_OTP = AppConfig.get().getString("otp.correct_code");

    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String path = req.getPathInfo();

        if ("POST".equals(req.getMethod()) && "/insecure-design/vulnerable".equals(path)) {
            handleVulnerable(req, res);
        } else if ("POST".equals(req.getMethod()) && "/insecure-design/mitigated".equals(path)) {
            handleMitigated(req, res);
        } else {
            renderPage(res, null, null);
        }
    }

    private void handleVulnerable(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String otp = req.getParameter("otp");
        String result = CORRECT_OTP.equals(otp)
            ? "<span class='text-green-700 font-semibold'>OTP accepted! Access granted.</span>"
            : "<span class='text-red-600'>Wrong OTP. Try again — no limit on attempts!</span>";
        renderPage(res, result, null);
    }

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
            "No rate limit or attempt counter exists on the OTP check endpoint. An attacker can " +
            "script thousands of guesses per second to brute-force a 6-digit OTP in under a minute.",
            "Enforce a per-session attempt limit (e.g. 5 attempts). Lock the flow after the limit " +
            "is exceeded and require re-authentication or a cooldown period. The limit is configurable " +
            "in <code>application.yml</code> under <code>otp.max_attempts</code>."
        );

        String hint = "<p class='text-xs text-gray-500 mt-2'>Hint: the OTP is <code>123456</code>. " +
                      "In the vulnerable panel you can submit unlimited wrong guesses first.</p>";

        String vulnForm = """
            <form method="POST" action="/insecure-design/vulnerable" class="space-y-3">
              <label class="block text-sm font-medium text-gray-700">Enter OTP</label>
              <input type="text" name="otp" placeholder="6-digit code"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"/>
              <button class="bg-red-600 text-white px-4 py-2 rounded text-sm hover:bg-red-700">Submit (No Limit)</button>
            </form>%s
            """.formatted(hint);

        String safeForm = """
            <form method="POST" action="/insecure-design/mitigated" class="space-y-3">
              <label class="block text-sm font-medium text-gray-700">Enter OTP</label>
              <input type="text" name="otp2" placeholder="6-digit code"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm"/>
              <button class="bg-green-600 text-white px-4 py-2 rounded text-sm hover:bg-green-700">Submit (Rate Limited)</button>
            </form>%s
            """.formatted(hint);

        String panels = """
            <div class="grid md:grid-cols-2 gap-6">%s%s</div>
            """.formatted(
                TemplateEngine.demoPanel("Vulnerable — No Rate Limit", "red", vulnForm,
                    vulnResult != null ? TemplateEngine.resultBox(vulnResult, false) : ""),
                TemplateEngine.demoPanel("Mitigated — Attempt Counter", "green", safeForm,
                    safeResult != null ? TemplateEngine.resultBox(safeResult, true) : "")
            );

        String exploits = TemplateEngine.exploitBox(new String[][]{
            {"Brute-force correct OTP", "123456",
             "This is the hardcoded correct value. In the vulnerable panel you can guess it after any number of wrong attempts.", "otp",
             "curl -s -X POST http://localhost:8090/insecure-design/vulnerable -b 'JSESSIONID=SESSION' -d 'otp=123456'"},
            {"Sequential guessing", "000000",
             "Script 000000 through 999999 — only 1 million combinations. No rate limit means this completes in seconds.", "otp",
             "for i in $(seq -w 0 999999); do curl -s -X POST http://localhost:8090/insecure-design/vulnerable -b 'JSESSIONID=SESSION' -d \"otp=$i\" | grep -q 'accepted' && echo \"Found: $i\" && break; done"},
            {"Common OTP", "111111",
             "Users often set PINs like 111111 or 123456. Try predictable codes first before brute-forcing.", "otp",
             "curl -s -X POST http://localhost:8090/insecure-design/vulnerable -b 'JSESSIONID=SESSION' -d 'otp=111111'"},
        });

        String content = TemplateEngine.vulnerabilityBadge("A04", "Insecure Design", "Design") + info + exploits + panels;
        res.getWriter().write(TemplateEngine.page("Insecure Design", content, true));
    }
}
