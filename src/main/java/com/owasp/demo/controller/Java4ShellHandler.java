package com.owasp.demo.controller;

import com.owasp.demo.config.AppConfig;
import com.owasp.demo.util.JvmExposureCheck;
import com.owasp.demo.util.JvmExposureCheck.Result;
import com.owasp.demo.util.Messages;
import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Java4Shell (CVE-2026-114938) demo. The bug is inside the JVM's native Base64 fast path,
 * so this page cannot trigger it. It reports whether this JVM and CPU match the advisory's
 * conditions, and shows an unchecked decode endpoint next to a validated one.
 */
@Controller
public class Java4ShellHandler {

    private static final Pattern STRICT_BASE64 = Pattern.compile("[A-Za-z0-9+/]*={0,2}");

    private final AppConfig cfg = AppConfig.get();
    private final int maxChars = cfg.getInt("java4shell.max_input_chars");
    private final int previewBytes = cfg.getInt("java4shell.preview_bytes");

    @GetMapping("/java4shell")
    public void page(HttpServletRequest req, HttpServletResponse res) throws IOException {
        renderPage(res, null, null, null, null);
    }

    @PostMapping("/java4shell/vulnerable")
    public void vulnerable(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String data = param(req, "data");
        renderPage(res, data, decode(data), null, null);
    }

    @PostMapping("/java4shell/mitigated")
    public void mitigated(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String data = param(req, "data2");
        renderPage(res, null, null, data, decodeValidated(data));
    }

    private String param(HttpServletRequest req, String name) {
        String v = req.getParameter(name);
        return v == null ? "" : v;
    }

    /**
     * Hands the text straight to the JDK decoder. No size limit, no alphabet check.
     *
     * @param data untrusted Base64 text
     * @return an HTML result box
     */
    private String decode(String data) {
        try {
            byte[] bytes = Base64.getDecoder().decode(data);
            return TemplateEngine.resultBox(describe(bytes) + " <em>No input checks ran.</em>", false);
        } catch (IllegalArgumentException e) {
            return TemplateEngine.resultBox("Decoder error: " + TemplateEngine.escape(e.getMessage()), false);
        }
    }

    /**
     * Checks size and alphabet first, then decodes. This narrows what an attacker can send.
     * It does not fix the JVM bug. Only a patch or a JVM flag does.
     *
     * @param data untrusted Base64 text
     * @return an HTML result box
     */
    private String decodeValidated(String data) {
        if (data.isEmpty()) {
            return TemplateEngine.resultBox("Rejected — input is empty.", false);
        }
        if (data.length() > maxChars) {
            return TemplateEngine.resultBox("Rejected — input is " + data.length()
                + " characters. The limit is " + maxChars + ".", false);
        }
        if (data.length() % 4 != 0 || !STRICT_BASE64.matcher(data).matches()) {
            return TemplateEngine.resultBox("Rejected — not strict Base64.", false);
        }
        byte[] bytes = Base64.getDecoder().decode(data);
        return TemplateEngine.resultBox(describe(bytes) + " Size and alphabet were checked first.", true);
    }

    private String describe(byte[] bytes) {
        int n = Math.min(bytes.length, previewBytes);
        byte[] head = java.util.Arrays.copyOf(bytes, n);
        String hex = HexFormat.of().formatHex(head);
        String text = new String(head, StandardCharsets.UTF_8).replaceAll("[^\\x20-\\x7E]", ".");
        return "Decoded " + bytes.length + " bytes.<br/>First " + n + " bytes (hex): <code>" + hex
            + "</code><br/>As text: <code>" + TemplateEngine.escape(text) + "</code>";
    }

    /**
     * @return the CPU flag names from /proc/cpuinfo, or null off Linux or if unreadable
     */
    private Set<String> readCpuFlags() {
        try {
            Path p = Path.of("/proc/cpuinfo");
            if (!Files.isReadable(p)) return null;
            for (String line : Files.readAllLines(p)) {
                if (line.startsWith("flags")) {
                    return Set.of(line.substring(line.indexOf(':') + 1).trim().split("\\s+"));
                }
            }
        } catch (IOException | RuntimeException e) {
            // Fall through. The check reports that flags could not be read.
        }
        return null;
    }

    private String exposureBox() {
        List<String> jvmArgs = ManagementFactory.getRuntimeMXBean().getInputArguments();
        Set<String> cpuFlags = readCpuFlags();
        List<String> needed = cfg.getStringList("java4shell.required_cpu_flags");
        List<Integer> affected = cfg.getStringList("java4shell.affected_java_versions").stream().map(Integer::parseInt).toList();
        String arch = System.getProperty("os.arch");

        Result r = JvmExposureCheck.assess(Runtime.version().feature(), arch, cpuFlags, jvmArgs,
            affected, needed, cfg.getStringList("java4shell.mitigation_flags"));

        String color = switch (r.verdict()) {
            case POSSIBLY_EXPOSED -> "red";
            case MITIGATED -> "yellow";
            case NOT_EXPOSED -> "green";
        };
        String label = switch (r.verdict()) {
            case POSSIBLY_EXPOSED -> "Possibly exposed";
            case MITIGATED -> "Mitigated by JVM flag";
            case NOT_EXPOSED -> "Not exposed";
        };
        String cpuText = cpuFlags == null ? "unknown (cannot read /proc/cpuinfo)"
            : cpuFlags.containsAll(needed) ? "has " + needed : "missing some of " + needed;

        return TemplateEngine.render("forms/java4shell-exposure.html", Map.of(
            "color", color,
            "label", label,
            "message", TemplateEngine.escape(r.message()),
            "java", TemplateEngine.escape(System.getProperty("java.version") + " (" + System.getProperty("java.vendor") + ")"),
            "arch", TemplateEngine.escape(arch),
            "cpu", TemplateEngine.escape(cpuText),
            "flags", TemplateEngine.escape(jvmArgs.isEmpty() ? "none" : String.join(" ", jvmArgs))
        ));
    }

    private void renderPage(HttpServletResponse res, String vulnInput, String vulnResult,
                            String safeInput, String safeResult) throws IOException {
        String info = TemplateEngine.infoBox(
            Messages.get("java4shell.info.explanation"),
            Messages.get("java4shell.info.mitigation")
        );

        String vulnForm = TemplateEngine.render("forms/java4shell-vulnerable.html", Map.of(
            "value", TemplateEngine.escape(vulnInput != null ? vulnInput : "")));
        String safeForm = TemplateEngine.render("forms/java4shell-mitigated.html", Map.of(
            "value", TemplateEngine.escape(safeInput != null ? safeInput : ""),
            "limit", String.valueOf(maxChars)));

        String panels = """
            <div class="grid md:grid-cols-2 gap-6">
              %s
              %s
            </div>
            """.formatted(
                TemplateEngine.demoPanel(Messages.get("java4shell.panel.vulnerable"), "red", vulnForm, vulnResult != null ? vulnResult : ""),
                TemplateEngine.demoPanel(Messages.get("java4shell.panel.mitigated"), "green", safeForm, safeResult != null ? safeResult : ""));

        String exploits = TemplateEngine.exploitBox(new String[][]{
            {"Plain Base64", "SGVsbG8gSmF2YTRTaGVsbA==",
             "A normal input. Both sides decode it. This is not an exploit.", "data",
             "curl -s -X POST http://localhost:8090/java4shell/vulnerable -b 'SESSION_COOKIE=SESSION' --data-urlencode 'data=SGVsbG8gSmF2YTRTaGVsbA=='"},
            {"Not Base64", "@@@not-base64@@@",
             "The unchecked side hands it to the decoder and shows its error. The validated side rejects it first.", "data",
             "curl -s -X POST http://localhost:8090/java4shell/mitigated -b 'SESSION_COOKIE=SESSION' --data-urlencode 'data2=@@@not-base64@@@'"},
            {"Oversized input", "AAAA… (100,000 characters)",
             "The unchecked side accepts any size. The validated side stops at the limit. The real exploit also needs a crafted string. None is shown here.", null,
             "curl -s -X POST http://localhost:8090/java4shell/mitigated -b 'SESSION_COOKIE=SESSION' --data-urlencode \"data2=$(head -c 100000 /dev/zero | tr '\\0' A)\""},
            {"Mitigation flags", "-XX:-UseBASE64Intrinsics",
             "Start the JVM with this flag, or with -XX:UseAVX=2 on x86-64, to avoid the faulty shortcut until you patch. Then reload this page.", null,
             "java -XX:-UseBASE64Intrinsics -jar app.jar"},
        });

        String content = TemplateEngine.vulnerabilityBadge(Messages.get("java4shell.badge.id"),
                Messages.get("java4shell.badge.name"), Messages.get("java4shell.badge.tag"))
            + info + exposureBox() + exploits + panels;
        res.getWriter().write(TemplateEngine.page(Messages.get("java4shell.title"), content, true));
    }
}
