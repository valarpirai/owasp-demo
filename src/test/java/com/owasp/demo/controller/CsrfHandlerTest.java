package com.owasp.demo.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class CsrfHandlerTest {

    private final CsrfHandler handler = new CsrfHandler();
    private HttpServletRequest req;
    private HttpServletResponse res;
    private HttpSession session;
    private Map<String, Object> attrs;
    private StringWriter responseBody;

    @BeforeEach
    void setup() throws Exception {
        req = mock(HttpServletRequest.class);
        res = mock(HttpServletResponse.class);
        session = mock(HttpSession.class);
        attrs = new HashMap<>();
        responseBody = new StringWriter();
        when(res.getWriter()).thenReturn(new PrintWriter(responseBody));
        when(req.getSession()).thenReturn(session);
        when(session.getAttribute(anyString())).thenAnswer(i -> attrs.get(i.<String>getArgument(0)));
        doAnswer(i -> attrs.put(i.getArgument(0), i.getArgument(1)))
            .when(session).setAttribute(anyString(), any());
    }

    private void post(String path, String email, String token) {
        when(req.getMethod()).thenReturn("POST");
        when(req.getPathInfo()).thenReturn(path);
        when(req.getParameter("email")).thenReturn(email);
        when(req.getParameter("csrfToken")).thenReturn(token);
    }

    @Test
    void vulnerableEndpoint_changesEmailWithoutToken() throws Exception {
        post("/csrf/vulnerable", "attacker@evil.example", null);

        handler.handle(req, res);

        assertEquals("attacker@evil.example", attrs.get("csrfEmailVulnerable"));
    }

    @Test
    void mitigatedEndpoint_rejectsRequestWithoutToken() throws Exception {
        attrs.put("csrfToken", "secret");
        post("/csrf/mitigated", "attacker@evil.example", null);

        handler.handle(req, res);

        verify(res).setStatus(403);
        assertNull(attrs.get("csrfEmailMitigated"));
    }

    @Test
    void mitigatedEndpoint_rejectsWrongToken() throws Exception {
        attrs.put("csrfToken", "secret");
        post("/csrf/mitigated", "attacker@evil.example", "guess");

        handler.handle(req, res);

        verify(res).setStatus(403);
        assertNull(attrs.get("csrfEmailMitigated"));
    }

    @Test
    void mitigatedEndpoint_acceptsValidToken() throws Exception {
        attrs.put("csrfToken", "secret");
        post("/csrf/mitigated", "bob@example.com", "secret");

        handler.handle(req, res);

        assertEquals("bob@example.com", attrs.get("csrfEmailMitigated"));
    }

    @Test
    void getPage_embedsSessionTokenInMitigatedForm() throws Exception {
        when(req.getMethod()).thenReturn("GET");
        when(req.getPathInfo()).thenReturn("/csrf");

        handler.handle(req, res);

        String token = (String) attrs.get("csrfToken");
        assertNotNull(token);
        assertTrue(responseBody.toString().contains("value=\"" + token + "\""));
    }

    @Test
    void attackPage_postsToRequestedTargetOnly() throws Exception {
        when(req.getMethod()).thenReturn("GET");
        when(req.getPathInfo()).thenReturn("/csrf/attack");
        when(req.getParameter("target")).thenReturn("\"><script>x</script>");

        handler.handle(req, res);

        String body = responseBody.toString();
        assertTrue(body.contains("action=\"/csrf/vulnerable\""));
        assertFalse(body.contains("<script>x</script>"));
    }
}
