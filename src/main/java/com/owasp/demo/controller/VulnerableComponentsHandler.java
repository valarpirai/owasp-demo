package com.owasp.demo.controller;

import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public class VulnerableComponentsHandler implements IRouteHandler {

    private record Dep(String name, String vulnVersion, String cve, String description, String fixVersion) {}

    private static final Dep[] DEPS = {
        new Dep("Apache Log4j",   "2.14.1", "CVE-2021-44228 (Log4Shell)", "Remote code execution via JNDI lookup in log messages.",         "2.17.1+"),
        new Dep("Spring Framework","5.3.17", "CVE-2022-22965 (Spring4Shell)","RCE via data-binding on JDK 9+ with Tomcat.",                    "5.3.18+"),
        new Dep("H2 Database",    "2.1.210", "CVE-2022-23221",            "Unauthenticated RCE via the H2 Console JDBC URL.",                 "2.1.212+"),
        new Dep("Jackson Databind","2.12.6","CVE-2022-42003",             "Deep wrapper array nesting causes stack overflow / DoS.",           "2.14.0+"),
        new Dep("Tomcat",         "10.0.20","CVE-2022-34305",             "XSS in the manager application via crafted session IDs.",          "10.0.21+"),
    };

    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        StringBuilder rows = new StringBuilder();
        for (Dep d : DEPS) {
            rows.append("""
                <tr class="border-b">
                  <td class="px-3 py-2 font-medium">%s</td>
                  <td class="px-3 py-2 text-red-600 font-mono text-xs">%s</td>
                  <td class="px-3 py-2 text-xs">
                    <span class="bg-red-100 text-red-800 px-1 py-0.5 rounded">%s</span>
                  </td>
                  <td class="px-3 py-2 text-xs text-gray-600">%s</td>
                  <td class="px-3 py-2 text-green-700 font-mono text-xs">%s</td>
                </tr>
                """.formatted(d.name(), d.vulnVersion(), d.cve(), d.description(), d.fixVersion()));
        }

        String info = TemplateEngine.infoBox(
            "Applications that use components with known public CVEs inherit those vulnerabilities. " +
            "Most supply-chain attacks exploit unpatched transitive dependencies that developers " +
            "are not even aware of.",
            "Maintain an SBOM (software bill of materials). Run <code>dependency-check</code> or " +
            "GitHub Dependabot in CI. Subscribe to CVE feeds for your runtime and framework. " +
            "Pin versions and upgrade regularly."
        );

        String table = """
            <div class="overflow-x-auto">
              <table class="w-full text-sm bg-white shadow rounded">
                <thead class="bg-gray-100 text-left">
                  <tr>
                    <th class="px-3 py-2">Component</th>
                    <th class="px-3 py-2">Vulnerable Version</th>
                    <th class="px-3 py-2">CVE</th>
                    <th class="px-3 py-2">Impact</th>
                    <th class="px-3 py-2">Fixed In</th>
                  </tr>
                </thead>
                <tbody>%s</tbody>
              </table>
            </div>
            """.formatted(rows);

        String content = TemplateEngine.vulnerabilityBadge("A06", "Vulnerable & Outdated Components")
            + info + table;
        res.getWriter().write(TemplateEngine.page("Vulnerable Components", content, true));
    }
}
