package com.owasp.demo.interceptor;

import com.owasp.demo.db.Database;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class ConsoleAuthFilterTest {

    private final ConsoleAuthFilter filter = new ConsoleAuthFilter();

    @BeforeAll
    static void setupDb() throws Exception {
        Database.init();
    }

    @Test
    void anonymousRequest_isRedirectedAndNeverReachesConsole() throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse res = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, res, chain);

        verify(res).sendRedirect("/login");
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void wrongBasicPassword_gets401() throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse res = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        when(req.getHeader("Authorization")).thenReturn("Basic " + Base64.getEncoder().encodeToString("admin:nope".getBytes()));

        filter.doFilter(req, res, chain);

        verify(res).setStatus(401);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void loggedInSession_reachesConsole() throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse res = mock(HttpServletResponse.class);
        HttpSession session = mock(HttpSession.class);
        FilterChain chain = mock(FilterChain.class);
        when(session.getAttribute("user")).thenReturn("admin");
        when(session.getId()).thenReturn("console-test");
        when(req.getSession(false)).thenReturn(session);

        filter.doFilter(req, res, chain);

        verify(chain).doFilter(req, res);
    }
}
