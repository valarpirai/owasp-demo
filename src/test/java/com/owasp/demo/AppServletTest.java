package com.owasp.demo;

import com.owasp.demo.db.Database;
import com.owasp.demo.model.AuditLog;
import com.owasp.demo.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AppServletTest {

    private static AppServlet servlet;

    @BeforeAll
    static void setup() throws Exception {
        Database.init();
        servlet = new AppServlet();
    }

    private void call(String method, String path, String param) throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse res = mock(HttpServletResponse.class);
        HttpSession session = mock(HttpSession.class);
        when(res.getWriter()).thenReturn(new PrintWriter(new StringWriter()));
        when(req.getMethod()).thenReturn(method);
        when(req.getPathInfo()).thenReturn(path);
        when(req.getSession(false)).thenReturn(session);
        when(req.getSession()).thenReturn(session);
        when(session.getAttribute("user")).thenReturn("admin");
        when(req.getParameter("comment")).thenReturn(param);
        when(req.getParameterNames()).thenReturn(
            param == null ? Collections.emptyEnumeration() : Collections.enumeration(List.of("comment")));
        servlet.service(req, res);
    }

    private boolean logged(String event, String detailPart) throws Exception {
        return new AuditLogRepository().findRecent(200).stream()
            .anyMatch(l -> event.equals(l.event()) && l.details().contains(detailPart));
    }

    @Test
    void demoView_isAudited() throws Exception {
        call("GET", "/xss", null);
        assertTrue(logged("DEMO_VIEW", "path=/xss status=0"));
    }

    @Test
    void vulnerableAndMitigatedPosts_areAuditedWithoutValues() throws Exception {
        call("POST", "/xss/vulnerable", "<script>secret-payload</script>");
        call("POST", "/xss/mitigated", "hello");
        assertTrue(logged("DEMO_VULNERABLE", "user=admin method=POST path=/xss/vulnerable"));
        assertTrue(logged("DEMO_MITIGATED", "path=/xss/mitigated"));
        assertTrue(logged("DEMO_VULNERABLE", "params=comment"));
        assertFalse(new AuditLogRepository().findRecent(200).stream()
            .anyMatch(l -> l.details() != null && l.details().contains("secret-payload")));
    }

    @Test
    void dashboard_isNotAudited() throws Exception {
        call("GET", "/", null);
        assertFalse(new AuditLogRepository().findRecent(200).stream()
            .anyMatch(l -> l.details() != null && l.details().contains("path=/ ")));
    }
}
