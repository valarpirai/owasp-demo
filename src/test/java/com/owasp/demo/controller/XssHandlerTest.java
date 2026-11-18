package com.owasp.demo.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class XssHandlerTest {

    private final XssHandler handler = new XssHandler();
    private HttpServletRequest req;
    private HttpServletResponse res;
    private StringWriter responseBody;

    @BeforeEach
    void setup() throws Exception {
        req = mock(HttpServletRequest.class);
        res = mock(HttpServletResponse.class);
        responseBody = new StringWriter();
        when(res.getWriter()).thenReturn(new PrintWriter(responseBody));
    }

    @Test
    void vulnerableEndpoint_reflectsScriptTagUnescaped() throws Exception {
        when(req.getMethod()).thenReturn("POST");
        when(req.getPathInfo()).thenReturn("/xss/vulnerable");
        when(req.getParameter("comment")).thenReturn("<script>alert('XSS')</script>");

        TestRoutes.call(handler, req, res);

        // The raw script tag is present in the response (the vulnerability)
        assertTrue(responseBody.toString().contains("<script>alert('XSS')</script>"));
    }

    @Test
    void mitigatedEndpoint_escapesScriptTag() throws Exception {
        when(req.getMethod()).thenReturn("POST");
        when(req.getPathInfo()).thenReturn("/xss/mitigated");
        when(req.getParameter("comment2")).thenReturn("<script>alert('XSS')</script>");

        TestRoutes.call(handler, req, res);

        String body = responseBody.toString();
        // The raw script tag must NOT appear — it must be escaped
        assertFalse(body.contains("<script>alert('XSS')</script>"));
        assertTrue(body.contains("&lt;script&gt;"));
    }

    @Test
    void mitigatedEndpoint_escapesEventHandler() throws Exception {
        when(req.getMethod()).thenReturn("POST");
        when(req.getPathInfo()).thenReturn("/xss/mitigated");
        when(req.getParameter("comment2")).thenReturn("<img src=x onerror=alert(1)>");

        TestRoutes.call(handler, req, res);

        String body = responseBody.toString();
        assertFalse(body.contains("<img src=x onerror=alert(1)>"));
        assertTrue(body.contains("&lt;img"));
    }

    @Test
    void getPage_rendersBothPanels() throws Exception {
        when(req.getMethod()).thenReturn("GET");
        when(req.getPathInfo()).thenReturn("/xss");

        TestRoutes.call(handler, req, res);

        String body = responseBody.toString();
        assertTrue(body.contains("/xss/vulnerable"));
        assertTrue(body.contains("/xss/mitigated"));
    }
}
