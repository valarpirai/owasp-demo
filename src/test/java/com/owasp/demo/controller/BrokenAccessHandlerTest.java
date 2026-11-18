package com.owasp.demo.controller;

import com.owasp.demo.db.Database;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class BrokenAccessHandlerTest {

    private static BrokenAccessHandler handler;
    private HttpServletRequest req;
    private HttpServletResponse res;
    private StringWriter responseBody;

    @BeforeAll
    static void setupDb() throws SQLException {
        Database.init();
        handler = new BrokenAccessHandler();
    }

    @BeforeEach
    void setup() throws Exception {
        req = mock(HttpServletRequest.class);
        res = mock(HttpServletResponse.class);
        responseBody = new StringWriter();
        when(res.getWriter()).thenReturn(new PrintWriter(responseBody));
    }

    @Test
    void vulnerableEndpoint_exposesPasswordsToAnyUser() throws Exception {
        when(req.getMethod()).thenReturn("GET");
        when(req.getPathInfo()).thenReturn("/bac/vulnerable");

        handler.handle(req, res);

        String body = responseBody.toString();
        // Passwords are visible in the vulnerable response
        assertTrue(body.contains("admin123") || body.contains("user123"));
    }

    @Test
    void mitigatedEndpoint_allows_adminRole() throws Exception {
        HttpSession session = mock(HttpSession.class);
        when(req.getMethod()).thenReturn("GET");
        when(req.getPathInfo()).thenReturn("/bac/mitigated");
        when(req.getSession(false)).thenReturn(session);
        when(session.getAttribute("role")).thenReturn("ADMIN");

        handler.handle(req, res);

        String body = responseBody.toString();
        // No passwords in the safe response — only username and role
        assertFalse(body.contains("admin123"));
        assertTrue(body.contains("admin"));
    }

    @Test
    void mitigatedEndpoint_returns403ForNonAdmin() throws Exception {
        HttpSession session = mock(HttpSession.class);
        when(req.getMethod()).thenReturn("GET");
        when(req.getPathInfo()).thenReturn("/bac/mitigated");
        when(req.getSession(false)).thenReturn(session);
        when(session.getAttribute("role")).thenReturn("USER");

        handler.handle(req, res);

        String body = responseBody.toString();
        assertTrue(body.contains("403"));
    }
}
