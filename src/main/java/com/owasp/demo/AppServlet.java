package com.owasp.demo;

import com.owasp.demo.config.AppConfig;
import com.owasp.demo.controller.*;
import com.owasp.demo.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class AppServlet extends HttpServlet {

    private final Map<String, IRouteHandler> routes = new HashMap<>();
    private final AuditLogRepository auditLog = new AuditLogRepository();

    private static final Set<String> PUBLIC_PATHS = Set.copyOf(AppConfig.get().getStringList("security.public_paths"));

    public AppServlet() {
        LoginHandler login = new LoginHandler();
        routes.put("GET /", new IndexHandler());
        routes.put("GET /login", login);
        routes.put("POST /login", login);
        routes.put("GET /logout", login);

        SqlInjectionHandler sqli = new SqlInjectionHandler();
        routes.put("GET /sqli", sqli);
        routes.put("POST /sqli/vulnerable", sqli);
        routes.put("POST /sqli/mitigated", sqli);

        XssHandler xss = new XssHandler();
        routes.put("GET /xss", xss);
        routes.put("POST /xss/vulnerable", xss);
        routes.put("POST /xss/mitigated", xss);

        BrokenAccessHandler bac = new BrokenAccessHandler();
        routes.put("GET /bac", bac);
        routes.put("GET /bac/vulnerable", bac);
        routes.put("GET /bac/mitigated", bac);

        CryptoFailuresHandler crypto = new CryptoFailuresHandler();
        routes.put("GET /crypto", crypto);
        routes.put("POST /crypto/vulnerable", crypto);
        routes.put("POST /crypto/mitigated", crypto);

        InsecureDesignHandler design = new InsecureDesignHandler();
        routes.put("GET /insecure-design", design);
        routes.put("POST /insecure-design/vulnerable", design);
        routes.put("POST /insecure-design/mitigated", design);

        SecurityMisconfigHandler misconfig = new SecurityMisconfigHandler();
        routes.put("GET /misconfig", misconfig);
        routes.put("GET /misconfig/vulnerable", misconfig);
        routes.put("GET /misconfig/mitigated", misconfig);

        VulnerableComponentsHandler vulnComp = new VulnerableComponentsHandler();
        routes.put("GET /vuln-components", vulnComp);

        AuthFailuresHandler auth = new AuthFailuresHandler();
        routes.put("GET /auth-failures", auth);
        routes.put("POST /auth-failures/vulnerable", auth);
        routes.put("POST /auth-failures/mitigated", auth);

        DataIntegrityHandler integrity = new DataIntegrityHandler();
        routes.put("GET /integrity", integrity);
        routes.put("POST /integrity/vulnerable", integrity);
        routes.put("POST /integrity/mitigated", integrity);

        LoggingMonitoringHandler logging = new LoggingMonitoringHandler();
        routes.put("GET /logging", logging);
        routes.put("POST /logging/vulnerable", logging);
        routes.put("POST /logging/mitigated", logging);

        SsrfHandler ssrf = new SsrfHandler();
        routes.put("GET /ssrf", ssrf);
        routes.put("POST /ssrf/vulnerable", ssrf);
        routes.put("POST /ssrf/mitigated", ssrf);

        RceHandler rce = new RceHandler();
        routes.put("GET /rce", rce);
        routes.put("POST /rce/vulnerable", rce);
        routes.put("POST /rce/mitigated", rce);

        CsrfHandler csrf = new CsrfHandler();
        routes.put("GET /csrf", csrf);
        routes.put("GET /csrf/attack", csrf);
        routes.put("POST /csrf/vulnerable", csrf);
        routes.put("POST /csrf/mitigated", csrf);

        DbBrowserHandler dbBrowser = new DbBrowserHandler();
        routes.put("GET /db-browser", dbBrowser);
        routes.put("GET /db-browser/table", dbBrowser);
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse res) throws IOException {
        res.setContentType("text/html;charset=UTF-8");
        AppConfig.get().getStringMap("security.headers").forEach(res::setHeader);

        String path = req.getPathInfo();
        if (path == null || path.isEmpty()) path = "/";

        if (!PUBLIC_PATHS.contains(path)) {
            HttpSession session = req.getSession(false);
            if (session == null || session.getAttribute("user") == null) {
                res.sendRedirect("/login");
                return;
            }
        }

        String key = req.getMethod() + " " + path;
        IRouteHandler handler = routes.get(key);

        if (handler != null) {
            handler.handle(req, res);
            if (isDemoPath(path)) auditDemo(req, res, path);
        } else {
            res.setStatus(404);
            res.getWriter().write("<h1>404 Not Found</h1><p>Path: " + path + "</p>");
        }
    }

    private boolean isDemoPath(String path) {
        return !"/".equals(path) && !PUBLIC_PATHS.contains(path);
    }

    /**
     * Writes one audit row for a demo request. Records the user, method, path,
     * status and parameter names. Parameter values are left out because demos
     * receive passwords and secrets. A failed write never breaks the request.
     *
     * @param req the request
     * @param res the response
     * @param path the matched path
     */
    private void auditDemo(HttpServletRequest req, HttpServletResponse res, String path) {
        try {
            HttpSession session = req.getSession(false);
            Object user = session != null ? session.getAttribute("user") : null;
            String event = path.endsWith("/vulnerable") ? "DEMO_VULNERABLE"
                : path.endsWith("/mitigated") ? "DEMO_MITIGATED" : "DEMO_VIEW";
            String params = req.getParameterNames() != null
                ? String.join(",", java.util.Collections.list(req.getParameterNames())) : "";
            String details = "user=%s method=%s path=%s status=%d params=%s"
                .formatted(user, req.getMethod(), path, res.getStatus(), params);
            auditLog.log(event, details.length() > 500 ? details.substring(0, 500) : details);
        } catch (Exception e) {
            // Auditing must not break the demo.
        }
    }
}
