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

class LoginHandlerTest {

    private static LoginHandler handler;
    private HttpServletRequest req;
    private HttpServletResponse res;
    private StringWriter responseBody;

    @BeforeAll
    static void setupDb() throws SQLException {
        Database.init();
        handler = new LoginHandler();
    }

    @BeforeEach
    void setup() throws Exception {
        req = mock(HttpServletRequest.class);
        res = mock(HttpServletResponse.class);
        responseBody = new StringWriter();
        when(res.getWriter()).thenReturn(new PrintWriter(responseBody));
    }

    @Test
    void getLoginPage_rendersFormWithHints() throws Exception {
        when(req.getMethod()).thenReturn("GET");
        when(req.getPathInfo()).thenReturn("/login");

        TestRoutes.call(handler, req, res);

        String body = responseBody.toString();
        assertTrue(body.contains("Sign In"));
        assertTrue(body.contains("admin"));
    }

    @Test
    void getLoginPage_listsUsersFromDatabase() throws Exception {
        when(req.getMethod()).thenReturn("GET");
        when(req.getPathInfo()).thenReturn("/login");

        TestRoutes.call(handler, req, res);

        String body = responseBody.toString();
        assertTrue(body.contains("data-user=\"admin\""));
        assertTrue(body.contains("data-user=\"user\""));
        assertTrue(body.contains("data-pass=\"admin123\""), "demo buttons use the seed password from config");
        assertFalse(body.contains("data-pass=\"$2a$"), "hashes are never put in the form");
    }

    @Test
    void postLogin_redirectsOnValidCredentials() throws Exception {
        HttpSession session = mock(HttpSession.class);
        when(req.getMethod()).thenReturn("POST");
        when(req.getPathInfo()).thenReturn("/login");
        when(req.getParameter("username")).thenReturn("admin");
        when(req.getParameter("password")).thenReturn("admin123");
        when(req.getSession(true)).thenReturn(session);
        when(session.getId()).thenReturn("redirect-test-session");

        TestRoutes.call(handler, req, res);

        verify(res).sendRedirect("/");
        verify(session).setAttribute("user", "admin");
        verify(session).setAttribute("role", "ADMIN");
    }

    @Test
    void postLogin_showsErrorOnInvalidCredentials() throws Exception {
        when(req.getMethod()).thenReturn("POST");
        when(req.getPathInfo()).thenReturn("/login");
        when(req.getParameter("username")).thenReturn("admin");
        when(req.getParameter("password")).thenReturn("wrongpass");

        TestRoutes.call(handler, req, res);

        String body = responseBody.toString();
        assertTrue(body.contains("Invalid username or password"));
        verify(res, never()).sendRedirect(anyString());
    }

    @Test
    void logout_invalidatesSessionAndRedirects() throws Exception {
        HttpSession session = mock(HttpSession.class);
        when(req.getMethod()).thenReturn("GET");
        when(req.getPathInfo()).thenReturn("/logout");
        when(req.getSession(false)).thenReturn(session);

        TestRoutes.call(handler, req, res);

        verify(session).invalidate();
        verify(res).sendRedirect("/login");
    }

    @Test
    void logout_handlesNoSession() throws Exception {
        when(req.getMethod()).thenReturn("GET");
        when(req.getPathInfo()).thenReturn("/logout");
        when(req.getSession(false)).thenReturn(null);

        TestRoutes.call(handler, req, res);

        verify(res).sendRedirect("/login");
    }

    @Test
    void successfulLogin_rotatesExistingSessionId() throws Exception {
        HttpSession session = mock(HttpSession.class);
        when(req.getMethod()).thenReturn("POST");
        when(req.getPathInfo()).thenReturn("/login");
        when(req.getParameter("username")).thenReturn("admin");
        when(req.getParameter("password")).thenReturn("admin123");
        when(req.getSession(false)).thenReturn(session);
        when(session.getId()).thenReturn("login-test-session");

        TestRoutes.call(handler, req, res);

        verify(req).changeSessionId();
        verify(session).setAttribute("user", "admin");
        assertTrue(new com.owasp.demo.repository.SessionRepository().exists("login-test-session"));
    }

    @Test
    void getLogin_redirectsWhenAlreadyLoggedIn() throws Exception {
        HttpSession session = mock(HttpSession.class);
        when(session.getAttribute("user")).thenReturn("admin");
        when(req.getMethod()).thenReturn("GET");
        when(req.getPathInfo()).thenReturn("/login");
        when(req.getSession(false)).thenReturn(session);

        TestRoutes.call(handler, req, res);

        verify(res).sendRedirect("/");
    }
}
