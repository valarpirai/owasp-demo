package com.owasp.demo.controller;

import com.owasp.demo.db.Database;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SqlInjectionHandlerTest {

    private static SqlInjectionHandler handler;
    private HttpServletRequest req;
    private HttpServletResponse res;
    private StringWriter responseBody;

    @BeforeAll
    static void setupDb() throws SQLException {
        Database.init();
        handler = new SqlInjectionHandler();
    }

    @BeforeEach
    void setup() throws Exception {
        req = mock(HttpServletRequest.class);
        res = mock(HttpServletResponse.class);
        responseBody = new StringWriter();
        when(res.getWriter()).thenReturn(new PrintWriter(responseBody));
    }

    @Test
    void getPage_rendersFormWithBothPanels() throws Exception {
        when(req.getMethod()).thenReturn("GET");
        when(req.getPathInfo()).thenReturn("/sqli");

        handler.handle(req, res);

        String body = responseBody.toString();
        assertTrue(body.contains("Vulnerable"));
        assertTrue(body.contains("Mitigated"));
        assertTrue(body.contains("/sqli/vulnerable"));
        assertTrue(body.contains("/sqli/mitigated"));
    }

    @Test
    void vulnerableEndpoint_returnsResultsForValidUser() throws Exception {
        when(req.getMethod()).thenReturn("POST");
        when(req.getPathInfo()).thenReturn("/sqli/vulnerable");
        when(req.getParameter("username")).thenReturn("admin");

        handler.handle(req, res);

        String body = responseBody.toString();
        assertTrue(body.contains("admin"));
    }

    @Test
    void vulnerableEndpoint_isExploitableWithInjection() throws Exception {
        when(req.getMethod()).thenReturn("POST");
        when(req.getPathInfo()).thenReturn("/sqli/vulnerable");
        when(req.getParameter("username")).thenReturn("' OR '1'='1");

        handler.handle(req, res);

        // Both users should be in the result — injection dumped the table
        String body = responseBody.toString();
        assertTrue(body.contains("admin"));
        assertTrue(body.contains("user"));
    }

    @Test
    void mitigatedEndpoint_resistsInjection() throws Exception {
        when(req.getMethod()).thenReturn("POST");
        when(req.getPathInfo()).thenReturn("/sqli/mitigated");
        when(req.getParameter("username2")).thenReturn("' OR '1'='1");

        handler.handle(req, res);

        // Injection string is not a real username — no results
        String body = responseBody.toString();
        assertTrue(body.contains("No results"));
    }

    @Test
    void mitigatedEndpoint_returnsUserForValidInput() throws Exception {
        when(req.getMethod()).thenReturn("POST");
        when(req.getPathInfo()).thenReturn("/sqli/mitigated");
        when(req.getParameter("username2")).thenReturn("admin");

        handler.handle(req, res);

        String body = responseBody.toString();
        assertTrue(body.contains("admin"));
    }
}
