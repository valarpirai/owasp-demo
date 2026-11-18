package com.owasp.demo.controller;

import com.owasp.demo.db.Database;
import com.owasp.demo.model.AuditLog;
import com.owasp.demo.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.sql.SQLException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class LoggingMonitoringHandlerTest {

    private static LoggingMonitoringHandler handler;
    private static AuditLogRepository auditRepo;
    private HttpServletRequest req;
    private HttpServletResponse res;
    private StringWriter responseBody;

    @BeforeAll
    static void setupDb() throws SQLException {
        Database.init();
        handler = new LoggingMonitoringHandler();
        auditRepo = new AuditLogRepository();
    }

    @BeforeEach
    void setup() throws Exception {
        req = mock(HttpServletRequest.class);
        res = mock(HttpServletResponse.class);
        responseBody = new StringWriter();
        when(res.getWriter()).thenReturn(new PrintWriter(responseBody));
    }

    @Test
    void vulnerableEndpoint_doesNotWriteAuditLog_onFailedLogin() throws Exception {
        List<AuditLog> before = auditRepo.findRecent(100);

        when(req.getMethod()).thenReturn("POST");
        when(req.getPathInfo()).thenReturn("/logging/vulnerable");
        when(req.getParameter("username")).thenReturn("admin");
        when(req.getParameter("password")).thenReturn("wrongpass");

        handler.handle(req, res);

        List<AuditLog> after = auditRepo.findRecent(100);
        assertEquals(before.size(), after.size(), "Vulnerable endpoint must not log failed logins");
    }

    @Test
    void mitigatedEndpoint_writesAuditLog_onFailedLogin() throws Exception {
        when(req.getMethod()).thenReturn("POST");
        when(req.getPathInfo()).thenReturn("/logging/mitigated");
        when(req.getParameter("username2")).thenReturn("admin");
        when(req.getParameter("password2")).thenReturn("wrongpass");

        handler.handle(req, res);

        List<AuditLog> logs = auditRepo.findRecent(5);
        assertTrue(logs.stream().anyMatch(l -> "LOGIN_FAILED".equals(l.event())));
    }

    @Test
    void mitigatedEndpoint_writesAuditLog_onSuccessfulLogin() throws Exception {
        when(req.getMethod()).thenReturn("POST");
        when(req.getPathInfo()).thenReturn("/logging/mitigated");
        when(req.getParameter("username2")).thenReturn("admin");
        when(req.getParameter("password2")).thenReturn("admin123");

        handler.handle(req, res);

        List<AuditLog> logs = auditRepo.findRecent(5);
        assertTrue(logs.stream().anyMatch(l -> "LOGIN_SUCCESS".equals(l.event())));
    }
}
