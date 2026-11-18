package com.owasp.demo.interceptor;

import com.owasp.demo.db.Database;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class InterceptorTest {

    private final AuthInterceptor auth = new AuthInterceptor();
    private HttpServletRequest req;
    private HttpServletResponse res;

    @BeforeAll
    static void setupDb() throws Exception {
        Database.init();
    }

    @BeforeEach
    void setup() {
        req = mock(HttpServletRequest.class);
        res = mock(HttpServletResponse.class);
    }

    @Test
    void auth_redirectsAnonymousUserToLogin() throws Exception {
        assertFalse(auth.preHandle(req, res, "/xss"));
        verify(res).sendRedirect("/login");
    }

    @Test
    void auth_redirectsSessionWithoutUser() throws Exception {
        when(req.getSession(false)).thenReturn(mock(HttpSession.class));
        assertFalse(auth.preHandle(req, res, "/xss"));
        verify(res).sendRedirect("/login");
    }

    @Test
    void auth_allowsPublicPathWithoutSession() throws Exception {
        assertTrue(auth.preHandle(req, res, "/login"));
        verify(res, never()).sendRedirect(anyString());
    }

    @Test
    void auth_allowsLoggedInUserEvenIfSessionRowIsMissing() throws Exception {
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute("user")).thenReturn("admin");
        when(session.getId()).thenReturn("no-such-row");
        when(req.getSession(false)).thenReturn(session);
        assertTrue(auth.preHandle(req, res, "/xss"));
    }

    private static String basic(String credentials) {
        return "Basic " + java.util.Base64.getEncoder().encodeToString(credentials.getBytes());
    }

    @Test
    void auth_acceptsValidBasicCredentials() throws Exception {
        HttpSession session = mock(HttpSession.class);
        when(req.getHeader("Authorization")).thenReturn(basic("admin:admin123"));
        when(req.getSession(true)).thenReturn(session);

        assertTrue(auth.preHandle(req, res, "/xss"));

        verify(session).setAttribute("user", "admin");
        verify(session).setAttribute("role", "ADMIN");
        verify(res, never()).sendRedirect(anyString());
    }

    @Test
    void auth_rejectsWrongBasicPasswordWith401() throws Exception {
        when(req.getHeader("Authorization")).thenReturn(basic("admin:wrong"));

        assertFalse(auth.preHandle(req, res, "/xss"));

        verify(res).setStatus(401);
        verify(res).setHeader(eq("WWW-Authenticate"), contains("Basic"));
    }

    @Test
    void auth_rejectsMalformedBasicHeaderWith401() throws Exception {
        when(req.getHeader("Authorization")).thenReturn("Basic !!!not-base64");

        assertFalse(auth.preHandle(req, res, "/xss"));

        verify(res).setStatus(401);
    }

    @Test
    void route_setsContentTypeAndSecurityHeaders() {
        RouteInterceptor route = new RouteInterceptor(auth);
        assertTrue(route.preHandle(req, res, "/xss"));
        verify(res).setContentType("text/html;charset=UTF-8");
        verify(res).setHeader("X-Frame-Options", "DENY");
        verify(res).setHeader("X-Content-Type-Options", "nosniff");
    }
}
