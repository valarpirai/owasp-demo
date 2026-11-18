package com.owasp.demo.controller;

import com.owasp.demo.util.Messages;
import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.util.List;

public class IndexHandler implements IRouteHandler {

    private record VulnCard(String id, String tag, String name, String path, String description) {}

    /** Cards are read from messages.yml, in list order. */
    private static final List<VulnCard> CARDS = Messages.getList("cards").stream()
        .map(c -> new VulnCard(c.get("id"), c.get("tag"), c.get("name"), c.get("path"), c.get("description")))
        .toList();

    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        HttpSession session = req.getSession(false);
        String user = session != null ? (String) session.getAttribute("user") : "?";

        StringBuilder cards = new StringBuilder();
        for (VulnCard c : CARDS) {
            cards.append("""
                <a href="%s" class="block bg-white rounded-lg shadow hover:shadow-md transition p-5 border-l-4 border-red-500">
                  <div class="flex items-center gap-2 mb-1">
                    <span class="bg-red-100 text-red-700 text-xs font-bold px-2 py-0.5 rounded">%s</span>
                    <span class="bg-gray-100 text-gray-700 text-xs font-semibold px-2 py-0.5 rounded">%s</span>
                  </div>
                  <h3 class="font-semibold text-gray-800 mb-1">%s</h3>
                  <p class="text-sm text-gray-500">%s</p>
                </a>
                """.formatted(c.path(), c.id(), c.tag(), c.name(), c.description()));
        }

        String content = """
            <div class="mb-8">
              <h1 class="text-3xl font-bold text-gray-800">OWASP Top 10 Vulnerability Demo</h1>
              <p class="text-gray-500 mt-1">Logged in as <strong>%s</strong>. Select a vulnerability to explore.</p>
            </div>
            <div class="grid sm:grid-cols-2 gap-4">
              %s
            </div>
            """.formatted(TemplateEngine.escape(user), cards);

        res.getWriter().write(TemplateEngine.page("Dashboard", content, true));
    }
}
