package com.owasp.demo.controller;

import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class DataIntegrityHandler implements IRouteHandler {

    private static final String HMAC_SECRET = "super-secret-hmac-key-not-in-prod";

    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String path = req.getServletPath();

        if ("POST".equals(req.getMethod()) && "/integrity/vulnerable".equals(path)) {
            handleVulnerable(req, res);
        } else if ("POST".equals(req.getMethod()) && "/integrity/mitigated".equals(path)) {
            handleMitigated(req, res);
        } else {
            renderPage(res, null, null);
        }
    }

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
            "The application deserialises Base64-encoded payloads from the client without any " +
            "integrity verification. An attacker can craft a payload granting themselves admin " +
            "privileges and the server will blindly accept it.",
            "Sign the payload with an HMAC-SHA256 key known only to the server. Verify the " +
            "signature before processing. Reject any payload where the signature does not match. " +
            "Never trust client-supplied data for privilege decisions."
        );

        String sample = samplePayload();
        String sig;
        try {
            sig = sampleSig();
        } catch (Exception e) {
            sig = "error";
        }

        String vulnForm = """
            <form method="POST" action="/integrity/vulnerable" class="space-y-3">
              <label class="block text-sm font-medium text-gray-700">Base64 payload</label>
              <input type="text" name="payload" value="%s"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm font-mono text-xs"/>
              <p class="text-xs text-gray-500">Modify the payload — server accepts anything.</p>
              <button class="bg-red-600 text-white px-4 py-2 rounded text-sm hover:bg-red-700">Submit (No Check)</button>
            </form>
            """.formatted(TemplateEngine.escape(sample));

        String safeForm = """
            <form method="POST" action="/integrity/mitigated" class="space-y-3">
              <label class="block text-sm font-medium text-gray-700">Base64 payload</label>
              <input type="text" name="payload2" value="%s"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm font-mono text-xs"/>
              <label class="block text-sm font-medium text-gray-700 mt-2">HMAC-SHA256 signature</label>
              <input type="text" name="sig" value="%s"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm font-mono text-xs"/>
              <p class="text-xs text-gray-500">Change payload without updating sig to see rejection.</p>
              <button class="bg-green-600 text-white px-4 py-2 rounded text-sm hover:bg-green-700">Submit (HMAC Verified)</button>
            </form>
            """.formatted(TemplateEngine.escape(sample), TemplateEngine.escape(sig));

        String panels = """
            <div class="grid md:grid-cols-2 gap-6">%s%s</div>
            """.formatted(
                TemplateEngine.demoPanel("Vulnerable — No Integrity Check", "red", vulnForm,
                    vulnResult != null ? TemplateEngine.resultBox(vulnResult, false) : ""),
                TemplateEngine.demoPanel("Mitigated — HMAC Signature Verified", "green", safeForm,
                    safeResult != null ? TemplateEngine.resultBox(safeResult, true) : "")
            );

        String content = TemplateEngine.vulnerabilityBadge("A08", "Software & Data Integrity Failures") + info + panels;
        res.getWriter().write(TemplateEngine.page("Data Integrity Failures", content, true));
    }
}
