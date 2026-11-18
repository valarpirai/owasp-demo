package com.owasp.demo.view;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class TemplateEngine {

    public static String render(String templateName, Map<String, String> vars) {
        String tpl = load(templateName);
        for (Map.Entry<String, String> e : vars.entrySet()) {
            tpl = tpl.replace("{" + e.getKey() + "}", e.getValue() != null ? e.getValue() : "");
        }
        return tpl;
    }

    public static String page(String title, String content, boolean loggedIn) {
        String nav = load(loggedIn ? "nav-auth.html" : "nav-public.html");
        return render("base.html", Map.of(
            "title", escape(title),
            "nav", nav,
            "content", content
        ));
    }

    public static String load(String name) {
        String path = "templates/" + name;
        try (InputStream in = TemplateEngine.class.getClassLoader().getResourceAsStream(path)) {
            if (in == null) throw new IllegalStateException("Template not found: " + path);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load template: " + path, e);
        }
    }

    public static String escape(String input) {
        if (input == null) return "";
        return input
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#x27;");
    }

    /**
     * Renders the page header with the category ID, a short demo tag, and the title.
     *
     * @param id OWASP category ID, such as A03
     * @param name page title
     * @param tag short demo label, such as SQLi
     * @return header HTML
     */
    public static String vulnerabilityBadge(String id, String name, String tag) {
        return """
            <div class="mb-6">
              <span class="bg-red-100 text-red-800 text-xs font-semibold px-2.5 py-1 rounded">%s</span>
              <span class="bg-gray-100 text-gray-700 text-xs font-semibold px-2.5 py-1 rounded">%s</span>
              <h1 class="text-2xl font-bold text-gray-800 mt-2">%s</h1>
            </div>
            """.formatted(id, escape(tag), name);
    }

    public static String infoBox(String explanation, String mitigation) {
        return """
            <div class="grid md:grid-cols-2 gap-4 mb-8">
              <div class="bg-red-50 border border-red-200 rounded-lg p-4">
                <h3 class="font-semibold text-red-700 mb-2">How the vulnerability works</h3>
                <p class="text-sm text-gray-700">%s</p>
              </div>
              <div class="bg-green-50 border border-green-200 rounded-lg p-4">
                <h3 class="font-semibold text-green-700 mb-2">How to mitigate</h3>
                <p class="text-sm text-gray-700">%s</p>
              </div>
            </div>
            """.formatted(explanation, mitigation);
    }

    public static String demoPanel(String label, String color, String formHtml, String resultHtml) {
        String border = color.equals("red") ? "border-red-300" : "border-green-300";
        String header = color.equals("red") ? "bg-red-600 text-white" : "bg-green-600 text-white";
        return """
            <div class="border %s rounded-lg overflow-hidden">
              <div class="%s px-4 py-2 font-semibold text-sm">%s</div>
              <div class="p-4 bg-white">%s%s</div>
            </div>
            """.formatted(border, header, label, formHtml, resultHtml);
    }

    /**
     * Renders a "Try These Payloads" box.
     * Each entry is String[]{title, payload, description} or String[]{title, payload, description, inputName}.
     * When inputName is supplied a "Use" button fills that form input with the payload.
     */
    public static String exploitBox(String[][] examples) {
        StringBuilder items = new StringBuilder();
        for (String[] ex : examples) {
            String title     = ex[0];
            String payload   = ex[1];
            String desc      = ex[2];
            String inputName = ex.length > 3 ? ex[3] : null;
            String curlCmd   = ex.length > 4 ? ex[4] : null;

            String useBtn = inputName != null
                ? ("<button type='button' onclick=\"document.querySelector('[name=%s]').value='%s'\" "
                  + "class='shrink-0 text-xs bg-blue-600 hover:bg-blue-700 text-white px-2 py-1 rounded'>Use ↗</button>")
                  .formatted(inputName, jsEscape(payload))
                : "";

            String curlBtn = curlCmd != null
                ? ("<button type='button' onclick=\"navigator.clipboard.writeText('%s')\" "
                  + "class='shrink-0 text-xs border border-gray-300 bg-gray-50 hover:bg-gray-100 px-2 py-1 rounded font-mono'>curl</button>")
                  .formatted(jsEscape(curlCmd))
                : "";

            items.append("""
                <div class="flex items-start gap-3 bg-white rounded p-3 border border-yellow-100">
                  <div class="flex-1 min-w-0">
                    <div class="font-medium text-sm text-gray-800">%s</div>
                    <code class="text-xs bg-gray-100 text-red-700 px-1.5 py-0.5 rounded mt-1 block break-all">%s</code>
                    <p class="text-xs text-gray-500 mt-1">%s</p>
                  </div>
                  <button type='button' onclick="navigator.clipboard.writeText('%s')"
                    class="shrink-0 text-xs border border-gray-300 hover:bg-gray-100 px-2 py-1 rounded">Copy</button>
                  %s
                  %s
                </div>
                """.formatted(escape(title), escape(payload), desc, jsEscape(payload), useBtn, curlBtn));
        }

        return """
            <div class="mb-6 bg-yellow-50 border border-yellow-200 rounded-lg p-4">
              <h3 class="font-semibold text-yellow-800 mb-3 text-sm">⚡ Exploit Payloads — Try These</h3>
              <div class="grid gap-2">%s</div>
            </div>
            """.formatted(items);
    }

    private static String jsEscape(String input) {
        if (input == null) return "";
        return input
            .replace("\\", "\\\\")
            .replace("'", "\\'")
            .replace("<", "\\x3C")
            .replace(">", "\\x3E")
            .replace("\n", "\\n")
            .replace("\r", "");
    }

    public static String resultBox(String result, boolean success) {
        if (result == null || result.isBlank()) return "";
        String cls = success
            ? "bg-green-50 border border-green-300 text-green-800"
            : "bg-red-50 border border-red-300 text-red-800";
        return "<div class=\"mt-3 p-3 rounded text-sm %s\">%s</div>".formatted(cls, result);
    }
}
