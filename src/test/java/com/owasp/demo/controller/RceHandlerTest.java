package com.owasp.demo.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class RceHandlerTest {

    private final RceHandler handler = new RceHandler();

    private String invoke(String method, String path, String paramName, String paramValue) throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse res = mock(HttpServletResponse.class);
        StringWriter sw = new StringWriter();
        when(req.getMethod()).thenReturn(method);
        when(req.getPathInfo()).thenReturn(path);
        when(req.getParameter(paramName)).thenReturn(paramValue);
        when(res.getWriter()).thenReturn(new PrintWriter(sw));
        TestRoutes.call(handler, req, res);
        return sw.toString();
    }

    @Test
    void vulnerable_safeHost_executesPing() throws Exception {
        String html = invoke("POST", "/rce/vulnerable", "host", "localhost");
        assertFalse(html.contains("DEMO SAFETY BLOCK"), "localhost should execute real ping");
        assertFalse(html.contains("INJECTION DETECTED"), "localhost has no injection");
    }

    @Test
    void vulnerable_lsInjection_isExecuted() throws Exception {
        String html = invoke("POST", "/rce/vulnerable", "host", "localhost; ls");
        assertFalse(html.contains("INJECTION BLOCKED"), "ls after a demo host is allowed");
        assertTrue(html.contains("build.gradle"), "ls output of the working directory is shown");
    }

    @Test
    void vulnerable_lsWithFlags_isExecuted() throws Exception {
        String html = invoke("POST", "/rce/vulnerable", "host", "localhost; ls -la");
        assertFalse(html.contains("INJECTION BLOCKED"));
        assertTrue(html.contains("build.gradle"));
    }

    @Test
    void vulnerable_nonLsInjection_blockedNotExecuted() throws Exception {
        String html = invoke("POST", "/rce/vulnerable", "host", "localhost && cat /etc/passwd");
        assertTrue(html.contains("INJECTION BLOCKED"), "Only ls may be injected");
        assertTrue(html.contains("ping -c 2 localhost &amp;&amp; cat /etc/passwd"), "Constructed command shown, HTML-escaped");
        assertFalse(html.contains("root:"), "cat must not run");
    }

    @Test
    void vulnerable_lsMixedWithOtherCommand_blocked() throws Exception {
        String html = invoke("POST", "/rce/vulnerable", "host", "localhost; ls; id");
        assertTrue(html.contains("INJECTION BLOCKED"));
    }

    @Test
    void vulnerable_lsWithSubstitutionOrRedirect_blocked() throws Exception {
        assertTrue(invoke("POST", "/rce/vulnerable", "host", "localhost; ls $(id)").contains("INJECTION BLOCKED"));
        assertTrue(invoke("POST", "/rce/vulnerable", "host", "localhost; ls > /tmp/x").contains("INJECTION BLOCKED"));
        assertTrue(invoke("POST", "/rce/vulnerable", "host", "localhost; ls `id`").contains("INJECTION BLOCKED"));
    }

    @Test
    void vulnerable_lsAfterNonDemoHost_blocked() throws Exception {
        String html = invoke("POST", "/rce/vulnerable", "host", "internal.corp.example; ls");
        assertTrue(html.contains("INJECTION BLOCKED"));
    }

    @Test
    void vulnerable_newlineInjection_blocked() throws Exception {
        String html = invoke("POST", "/rce/vulnerable", "host", "localhost\nid");
        assertTrue(html.contains("INJECTION BLOCKED"));
    }

    @Test
    void vulnerable_unknownHost_safetyBlockShown() throws Exception {
        String html = invoke("POST", "/rce/vulnerable", "host", "internal.corp.example");
        assertTrue(html.contains("DEMO SAFETY BLOCK"), "Non-demo host must be blocked");
        assertTrue(html.contains("internal.corp.example"), "Hostname echoed in block message");
    }

    @Test
    void mitigated_injectionPayload_rejected() throws Exception {
        String html = invoke("POST", "/rce/mitigated", "host2", "localhost; rm -rf /");
        assertTrue(html.contains("invalid characters"), "Mitigated path rejects metacharacters");
    }

    @Test
    void mitigated_safeHost_accepted() throws Exception {
        String html = invoke("POST", "/rce/mitigated", "host2", "localhost");
        assertFalse(html.contains("invalid characters"), "localhost is valid for mitigated path");
    }

    @Test
    void get_rendersPage() throws Exception {
        String html = invoke("GET", "/rce", "host", null);
        assertTrue(html.contains("OS Command"), "Page title present");
        assertTrue(html.contains("Exploit Payloads"), "Exploit box present");
    }
}
