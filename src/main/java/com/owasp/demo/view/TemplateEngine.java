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

    public static String vulnerabilityBadge(String id, String name) {
        return """
            <div class="mb-6">
              <span class="bg-red-100 text-red-800 text-xs font-semibold px-2.5 py-1 rounded">%s</span>
              <h1 class="text-2xl font-bold text-gray-800 mt-2">%s</h1>
            </div>
            """.formatted(id, name);
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

    public static String resultBox(String result, boolean success) {
        if (result == null || result.isBlank()) return "";
        String cls = success
            ? "bg-green-50 border border-green-300 text-green-800"
            : "bg-red-50 border border-red-300 text-red-800";
        return "<div class=\"mt-3 p-3 rounded text-sm %s\">%s</div>".formatted(cls, result);
    }
}
