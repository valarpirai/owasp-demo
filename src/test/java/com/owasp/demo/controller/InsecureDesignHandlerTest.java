package com.owasp.demo.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class InsecureDesignHandlerTest {

    private final InsecureDesignHandler handler = new InsecureDesignHandler();
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
    void vulnerableEndpoint_acceptsCorrectOtp() throws Exception {
        when(req.getMethod()).thenReturn("POST");
        when(req.getPathInfo()).thenReturn("/insecure-design/vulnerable");
        when(req.getParameter("otp")).thenReturn("123456");

        handler.handle(req, res);

        assertTrue(responseBody.toString().contains("Access granted"));
    }

    @Test
    void vulnerableEndpoint_rejectsWrongOtpButAllowsRetry() throws Exception {
        when(req.getMethod()).thenReturn("POST");
        when(req.getPathInfo()).thenReturn("/insecure-design/vulnerable");
        when(req.getParameter("otp")).thenReturn("000000");

        handler.handle(req, res);

        String body = responseBody.toString();
        assertTrue(body.contains("Wrong OTP"));
        assertTrue(body.contains("no limit"));
    }

    @Test
    void mitigatedEndpoint_locksAfterMaxAttempts() throws Exception {
        HttpSession session = mock(HttpSession.class);
        AtomicInteger counter = new AtomicInteger(5); // already at max
        when(req.getMethod()).thenReturn("POST");
        when(req.getPathInfo()).thenReturn("/insecure-design/mitigated");
        when(req.getSession(true)).thenReturn(session);
        when(session.getAttribute("otp_attempts")).thenReturn(counter);

        handler.handle(req, res);

        assertTrue(responseBody.toString().contains("locked"));
    }

    @Test
    void mitigatedEndpoint_acceptsCorrectOtpAndClearsCounter() throws Exception {
        HttpSession session = mock(HttpSession.class);
        AtomicInteger counter = new AtomicInteger(1);
        when(req.getMethod()).thenReturn("POST");
        when(req.getPathInfo()).thenReturn("/insecure-design/mitigated");
        when(req.getParameter("otp2")).thenReturn("123456");
        when(req.getSession(true)).thenReturn(session);
        when(session.getAttribute("otp_attempts")).thenReturn(counter);

        handler.handle(req, res);

        verify(session).removeAttribute("otp_attempts");
        assertTrue(responseBody.toString().contains("Access granted"));
    }
}
