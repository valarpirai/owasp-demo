package com.owasp.demo.controller;

import com.owasp.demo.util.Messages;
import com.owasp.demo.config.AppConfig;
import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Map;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

@Controller
public class DataIntegrityHandler {

    private static final String HMAC_SECRET = AppConfig.get().getHmacSecret();

    @GetMapping("/integrity")
    public void page(HttpServletRequest req, HttpServletResponse res) throws IOException {
        renderPage(res, null, null);
    }

    @PostMapping("/integrity/vulnerable")
    private void handleVulnerable(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String payload = req.getParameter("payload");
        String result;
        try {
            byte[] decoded = Base64.getDecoder().decode(payload);
            String json = new String(decoded, StandardCharsets.UTF_8);
            result = "<span class='text-red-600'>Deserialised without verification:</span><br/>" +
                     "<code class='text-xs bg-gray-100 p-1 rounded block mt-1'>" +
                     TemplateEngine.escape(json) + "</code><br/>" +
                     "<span class='text-red-600 text-xs'>No integrity check — attacker can forge any payload.</span>";
        } catch (Exception e) {
            result = "Error decoding payload: " + TemplateEngine.escape(e.getMessage());
        }
        renderPage(res, result, null);
    }

    @PostMapping("/integrity/mitigated")
    private void handleMitigated(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String payload = req.getParameter("payload2");
        String signature = req.getParameter("sig");
        String result;
        try {
            String expected = hmac(payload);
            if (!expected.equals(signature)) {
                result = "<span class='text-red-600 font-semibold'>Integrity check FAILED — signature mismatch. " +
                         "Payload rejected.</span>";
            } else {
                byte[] decoded = Base64.getDecoder().decode(payload);
                String json = new String(decoded, StandardCharsets.UTF_8);
                result = "<span class='text-green-700'>Signature valid. Payload accepted:</span><br/>" +
                         "<code class='text-xs bg-gray-100 p-1 rounded block mt-1'>" +
                         TemplateEngine.escape(json) + "</code>";
            }
        } catch (Exception e) {
            result = "Error: " + TemplateEngine.escape(e.getMessage());
        }
        renderPage(res, null, result);
    }

    private String hmac(String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(HMAC_SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return Base64.getEncoder().encodeToString(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    private String samplePayload() {
        String json = "{\"user\":\"admin\",\"role\":\"ADMIN\"}";
        return Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private String sampleSig() throws Exception {
        return hmac(samplePayload());
    }

    private void renderPage(HttpServletResponse res, String vulnResult, String safeResult) throws IOException {
        String info = TemplateEngine.infoBox(
            Messages.get("integrity.info.explanation"),
            Messages.get("integrity.info.mitigation")
        );

        String sample = samplePayload();
        String sig;
        try {
            sig = sampleSig();
        } catch (Exception e) {
            sig = "error";
        }

        String vulnForm = TemplateEngine.render("forms/integrity-vulnerable.html", Map.of(
            "payload", TemplateEngine.escape(sample)
        ));

        String safeForm = TemplateEngine.render("forms/integrity-mitigated.html", Map.of(
            "payload", TemplateEngine.escape(sample),
            "signature", TemplateEngine.escape(sig)
        ));

        String panels = """
            <div class="grid md:grid-cols-2 gap-6">%s%s</div>
            """.formatted(
                TemplateEngine.demoPanel(Messages.get("integrity.panel.vulnerable"), "red", vulnForm,
                    vulnResult != null ? TemplateEngine.resultBox(vulnResult, false) : ""),
                TemplateEngine.demoPanel(Messages.get("integrity.panel.mitigated"), "green", safeForm,
                    safeResult != null ? TemplateEngine.resultBox(safeResult, true) : "")
            );

        String exploits = TemplateEngine.exploitBox(new String[][]{
            {"Forge admin role", "eyJ1c2VyIjoiZXZpbCIsInJvbGUiOiJBRE1JTiJ9",
             "Base64 of {\"user\":\"evil\",\"role\":\"ADMIN\"}. Paste this in the vulnerable panel — no signature needed.", "payload",
             "curl -s -X POST http://localhost:8090/integrity/vulnerable -b 'SESSION_COOKIE=SESSION' -d 'payload=eyJ1c2VyIjoiZXZpbCIsInJvbGUiOiJBRE1JTiJ9'"},
            {"Modify existing payload", sample,
             "Copy the pre-filled payload, decode it, change user to 'hacker', re-encode, and submit — server accepts it.", "payload",
             "echo '{\"user\":\"hacker\",\"role\":\"ADMIN\"}' | base64 | xargs -I{} curl -s -X POST http://localhost:8090/integrity/vulnerable -b 'SESSION_COOKIE=SESSION' -d 'payload={}'"},
            {"Tamper signed payload", sample,
             "Use the same payload in the mitigated panel but leave the original signature — it will be rejected.", "payload2",
             "curl -s -X POST http://localhost:8090/integrity/mitigated -b 'SESSION_COOKIE=SESSION' -d 'payload=eyJ1c2VyIjoiZXZpbCIsInJvbGUiOiJBRE1JTiJ9&sig=invalidsignature'"},
        });

        String content = TemplateEngine.vulnerabilityBadge(Messages.get("integrity.badge.id"), Messages.get("integrity.badge.name"), Messages.get("integrity.badge.tag")) + info + exploits + panels;
        res.getWriter().write(TemplateEngine.page(Messages.get("integrity.title"), content, true));
    }
}
