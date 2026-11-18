package com.owasp.demo.interceptor;

import com.owasp.demo.config.AppConfig;
import com.owasp.demo.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.util.Collections;

/**
 * Per-route concerns. Before the handler it sets the content type and the
 * security headers. After it, it writes one audit row for each demo request.
 */
public class RouteInterceptor implements Interceptor {

    private static final int MAX_DETAILS = 500;

    private final AuditLogRepository auditLog = new AuditLogRepository();
    private final AuthInterceptor auth;

    /**
     * @param auth used to tell public paths from demo paths
     */
    public RouteInterceptor(AuthInterceptor auth) {
        this.auth = auth;
    }

    @Override
    public boolean preHandle(HttpServletRequest req, HttpServletResponse res, String path) {
        res.setContentType("text/html;charset=UTF-8");
        AppConfig.get().getStringMap("security.headers").forEach(res::setHeader);
        return true;
    }

    @Override
    public void afterHandle(HttpServletRequest req, HttpServletResponse res, String path) {
        if (!isDemoPath(path)) return;
        try {
            HttpSession session = req.getSession(false);
            Object user = session != null ? session.getAttribute("user") : null;
            String event = path.endsWith("/vulnerable") ? "DEMO_VULNERABLE"
                : path.endsWith("/mitigated") ? "DEMO_MITIGATED" : "DEMO_VIEW";
            String params = req.getParameterNames() != null
                ? String.join(",", Collections.list(req.getParameterNames())) : "";
            String details = "user=%s method=%s path=%s status=%d params=%s"
                .formatted(user, req.getMethod(), path, res.getStatus(), params);
            // Values are left out on purpose. Demos receive passwords and secrets.
            auditLog.log(event, details.length() > MAX_DETAILS ? details.substring(0, MAX_DETAILS) : details);
        } catch (Exception e) {
            // Auditing must not break the demo.
        }
    }

    private boolean isDemoPath(String path) {
        return !"/".equals(path) && !auth.isPublic(path);
    }
}
