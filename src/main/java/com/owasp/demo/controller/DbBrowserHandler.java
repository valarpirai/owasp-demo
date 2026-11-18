package com.owasp.demo.controller;

import com.owasp.demo.config.AppConfig;
import com.owasp.demo.repository.DbBrowserRepository;
import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@Controller
public class DbBrowserHandler {

    private static final int DEFAULT_PAGE_SIZE = AppConfig.get().getInt("db_browser.default_page_size");
    private final DbBrowserRepository repo = new DbBrowserRepository();

    @GetMapping("/db-browser")
    private void renderIndex(HttpServletRequest req, HttpServletResponse res) throws IOException {
        List<String> tables;
        try {
            tables = repo.getTables();
        } catch (Exception e) {
            res.getWriter().write(TemplateEngine.page("DB Browser",
                "<p class='text-red-600'>Error: " + TemplateEngine.escape(e.getMessage()) + "</p>", true));
            return;
        }

        StringBuilder cards = new StringBuilder();
        for (String t : tables) {
            cards.append("""
                <a href="/db-browser/table?table=%s"
                   class="block bg-white rounded-lg shadow hover:shadow-md p-5 border-l-4 border-blue-500 transition">
                  <div class="font-semibold text-gray-800">%s</div>
                  <div class="text-xs text-gray-400 mt-1">click to browse</div>
                </a>
                """.formatted(t, t));
        }

        String content = """
            <div class="mb-6">
              <h1 class="text-2xl font-bold text-gray-800">Database Browser</h1>
              <p class="text-gray-500 text-sm mt-1">H2 in-memory — PUBLIC schema</p>
            </div>
            <div class="grid sm:grid-cols-3 gap-4">%s</div>
            """.formatted(cards);

        res.getWriter().write(TemplateEngine.page("DB Browser", content, true));
    }

    @GetMapping("/db-browser/table")
    private void renderTable(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String table    = req.getParameter("table");
        String filter   = req.getParameter("filter");
        String sortCol  = req.getParameter("sort");
        String sortDir  = req.getParameter("dir");
        int page        = parseIntOr(req.getParameter("page"), 1);
        int pageSize    = parseIntOr(req.getParameter("size"), DEFAULT_PAGE_SIZE);

        if (page < 1) page = 1;
        if (pageSize < 1 || pageSize > 100) pageSize = DEFAULT_PAGE_SIZE;

        try {
            List<String> allTables = repo.getTables();
            if (table == null || !allTables.contains(table)) {
                res.sendRedirect("/db-browser");
                return;
            }

            List<String> columns = repo.getColumns(table);
            if (columns.isEmpty()) {
                res.sendRedirect("/db-browser");
                return;
            }

            if (sortCol == null || !columns.contains(sortCol)) sortCol = columns.getFirst();
            if (!"DESC".equalsIgnoreCase(sortDir)) sortDir = "ASC";

            int total     = repo.countRows(table, filter, columns);
            int totalPages = Math.max(1, (int) Math.ceil((double) total / pageSize));
            if (page > totalPages) page = totalPages;
            int offset = (page - 1) * pageSize;

            List<Map<String, Object>> rows = repo.fetchPage(table, columns, filter, sortCol, sortDir, offset, pageSize);

            String html = buildTableHtml(table, columns, rows, filter, sortCol, sortDir,
                                         page, pageSize, total, totalPages, allTables);
            res.getWriter().write(TemplateEngine.page("DB Browser — " + table, html, true));

        } catch (Exception e) {
            res.getWriter().write(TemplateEngine.page("DB Browser",
                "<p class='text-red-600'>Error: " + TemplateEngine.escape(e.getMessage()) + "</p>", true));
        }
    }

    private String buildTableHtml(
            String table, List<String> columns, List<Map<String, Object>> rows,
            String filter, String sortCol, String sortDir,
            int page, int pageSize, int total, int totalPages,
            List<String> allTables) {

        String baseUrl = "/db-browser/table?table=" + table;

        // table selector
        StringBuilder selector = new StringBuilder("<select onchange=\"location='/db-browser/table?table='+this.value\" "
            + "class=\"border border-gray-300 rounded px-3 py-1.5 text-sm\">");
        for (String t : allTables) {
            selector.append("<option value=\"").append(t).append("\"")
                    .append(t.equals(table) ? " selected" : "").append(">").append(t).append("</option>");
        }
        selector.append("</select>");

        // filter bar
        String filterBar = """
            <form method="GET" action="/db-browser/table" class="flex gap-2">
              <input type="hidden" name="table" value="%s"/>
              <input type="hidden" name="sort" value="%s"/>
              <input type="hidden" name="dir" value="%s"/>
              <input type="hidden" name="size" value="%d"/>
              <input type="text" name="filter" value="%s" placeholder="Search across all columns…"
                class="border border-gray-300 rounded px-3 py-1.5 text-sm w-72"/>
              <button class="bg-blue-600 text-white px-4 py-1.5 rounded text-sm hover:bg-blue-700">Filter</button>
              %s
            </form>
            """.formatted(
                table, sortCol, sortDir, pageSize,
                TemplateEngine.escape(filter != null ? filter : ""),
                (filter != null && !filter.isBlank())
                    ? "<a href=\"" + baseUrl + "\" class=\"px-3 py-1.5 text-sm border rounded hover:bg-gray-100\">Clear</a>"
                    : ""
            );

        // column headers with sort links
        StringBuilder headers = new StringBuilder();
        for (String col : columns) {
            String newDir = col.equals(sortCol) && "ASC".equals(sortDir) ? "DESC" : "ASC";
            String arrow  = col.equals(sortCol) ? ("ASC".equals(sortDir) ? " ↑" : " ↓") : "";
            String href   = baseUrl + "&sort=" + col + "&dir=" + newDir + "&page=1&size=" + pageSize
                            + (filter != null && !filter.isBlank() ? "&filter=" + TemplateEngine.escape(filter) : "");
            headers.append("<th class='px-3 py-2 text-left font-semibold whitespace-nowrap'>"
                + "<a href=\"" + href + "\" class='hover:text-blue-600'>" + col + arrow + "</a></th>");
        }

        // data rows
        StringBuilder dataRows = new StringBuilder();
        if (rows.isEmpty()) {
            dataRows.append("<tr><td colspan=\"").append(columns.size())
                    .append("\" class='px-3 py-4 text-center text-gray-400'>No rows found.</td></tr>");
        } else {
            for (Map<String, Object> row : rows) {
                dataRows.append("<tr class='border-b hover:bg-gray-50'>");
                for (Object val : row.values()) {
                    String cell = val == null ? "<span class='text-gray-300'>null</span>" : TemplateEngine.escape(val.toString());
                    dataRows.append("<td class='px-3 py-2 text-sm max-w-xs truncate'>").append(cell).append("</td>");
                }
                dataRows.append("</tr>");
            }
        }

        // pagination
        String filterParam = (filter != null && !filter.isBlank()) ? "&filter=" + TemplateEngine.escape(filter) : "";
        String sortParam   = "&sort=" + sortCol + "&dir=" + sortDir + "&size=" + pageSize;

        StringBuilder pager = new StringBuilder();
        pager.append("<div class='flex items-center gap-2 text-sm'>");
        pager.append("<span class='text-gray-500'>")
             .append(total).append(" row").append(total != 1 ? "s" : "")
             .append(", page ").append(page).append(" of ").append(totalPages).append("</span>");

        pager.append("<div class='flex gap-1 ml-4'>");
        appendPageBtn(pager, "«", 1, page, baseUrl + sortParam + filterParam);
        appendPageBtn(pager, "‹", page - 1, page, baseUrl + sortParam + filterParam);
        for (int p = Math.max(1, page - 2); p <= Math.min(totalPages, page + 2); p++) {
            String active = p == page ? "bg-blue-600 text-white" : "border hover:bg-gray-100";
            pager.append("<a href='").append(baseUrl).append(sortParam).append(filterParam)
                 .append("&page=").append(p).append("' class='px-2.5 py-1 rounded text-sm ").append(active).append("'>")
                 .append(p).append("</a>");
        }
        appendPageBtn(pager, "›", page + 1, page, baseUrl + sortParam + filterParam);
        appendPageBtn(pager, "»", totalPages, page, baseUrl + sortParam + filterParam);
        pager.append("</div>");

        // page size selector
        pager.append("<select onchange=\"location='").append(baseUrl).append(sortParam.replaceFirst("&size=\\d+", ""))
             .append(filterParam).append("&page=1&size='+this.value\" class='border rounded px-2 py-1 text-sm ml-2'>");
        for (int s : new int[]{10, 25, 50, 100}) {
            pager.append("<option value='").append(s).append("'").append(s == pageSize ? " selected" : "").append(">")
                 .append(s).append(" / page</option>");
        }
        pager.append("</select></div>");

        return """
            <div class="mb-4 flex items-center gap-4 flex-wrap">
              <a href="/db-browser" class="text-blue-600 text-sm hover:underline">← Tables</a>
              %s
            </div>
            <div class="mb-4 flex items-center gap-4 flex-wrap">
              %s
            </div>
            <div class="overflow-x-auto bg-white shadow rounded">
              <table class="w-full text-sm">
                <thead class="bg-gray-100 border-b"><tr>%s</tr></thead>
                <tbody>%s</tbody>
              </table>
            </div>
            <div class="mt-4">%s</div>
            """.formatted(selector, filterBar, headers, dataRows, pager);
    }

    private void appendPageBtn(StringBuilder sb, String label, int targetPage, int currentPage, String baseUrl) {
        boolean disabled = targetPage < 1;
        if (disabled) {
            sb.append("<span class='px-2.5 py-1 rounded text-gray-300 border'>").append(label).append("</span>");
        } else {
            sb.append("<a href='").append(baseUrl).append("&page=").append(targetPage)
              .append("' class='px-2.5 py-1 rounded border hover:bg-gray-100'>").append(label).append("</a>");
        }
    }

    private int parseIntOr(String val, int fallback) {
        if (val == null) return fallback;
        try { return Integer.parseInt(val); } catch (NumberFormatException e) { return fallback; }
    }
}
