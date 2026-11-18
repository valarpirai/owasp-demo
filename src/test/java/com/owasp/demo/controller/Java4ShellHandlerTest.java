package com.owasp.demo.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class Java4ShellHandlerTest {

    private final Java4ShellHandler handler = new Java4ShellHandler();

    private String invoke(String method, String path, String param, String value) throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse res = mock(HttpServletResponse.class);
        StringWriter sw = new StringWriter();
        when(req.getMethod()).thenReturn(method);
        when(req.getPathInfo()).thenReturn(path);
        if (param != null) when(req.getParameter(param)).thenReturn(value);
        when(res.getWriter()).thenReturn(new PrintWriter(sw));
        handler.handle(req, res);
        return sw.toString();
    }

    @Test
    void vulnerable_decodesValidInput() throws Exception {
        String html = invoke("POST", "/java4shell/vulnerable", "data", "SGVsbG8gSmF2YTRTaGVsbA==");
        assertTrue(html.contains("Decoded 16 bytes"));
        assertTrue(html.contains("Hello Java4Shell"));
        assertTrue(html.contains("No input checks ran"));
    }

    @Test
    void vulnerable_acceptsOversizedInput() throws Exception {
        String html = invoke("POST", "/java4shell/vulnerable", "data", "A".repeat(8000));
        assertTrue(html.contains("Decoded 6000 bytes"), "no size limit on the unchecked side");
    }

    @Test
    void vulnerable_showsDecoderErrorForBadInput() throws Exception {
        String html = invoke("POST", "/java4shell/vulnerable", "data", "@@@not-base64@@@");
        assertTrue(html.contains("Decoder error"));
    }

    @Test
    void mitigated_decodesValidInput() throws Exception {
        String html = invoke("POST", "/java4shell/mitigated", "data2", "SGVsbG8gSmF2YTRTaGVsbA==");
        assertTrue(html.contains("Decoded 16 bytes"));
        assertTrue(html.contains("checked first"));
    }

    @Test
    void mitigated_rejectsOversizedInput() throws Exception {
        String html = invoke("POST", "/java4shell/mitigated", "data2", "A".repeat(8000));
        assertTrue(html.contains("Rejected"));
        assertTrue(html.contains("limit is 4096"));
        assertFalse(html.contains("Decoded 6000 bytes"));
    }

    @Test
    void mitigated_rejectsBadAlphabetAndBadLength() throws Exception {
        assertTrue(invoke("POST", "/java4shell/mitigated", "data2", "@@@@").contains("not strict Base64"));
        assertTrue(invoke("POST", "/java4shell/mitigated", "data2", "QUJD=").contains("not strict Base64"));
        assertTrue(invoke("POST", "/java4shell/mitigated", "data2", "QUJDRA").contains("not strict Base64"));
        assertTrue(invoke("POST", "/java4shell/mitigated", "data2", "").contains("empty"));
    }

    @Test
    void echoedInputIsEscaped() throws Exception {
        String html = invoke("POST", "/java4shell/vulnerable", "data", "<script>x</script>");
        assertFalse(html.contains("<script>x</script>"));
        assertTrue(html.contains("&lt;script&gt;"));
    }

    @Test
    void getPage_showsExposureBoxAndBothForms() throws Exception {
        String html = invoke("GET", "/java4shell", null, null);
        assertTrue(html.contains("Is this server exposed?"));
        assertTrue(html.contains("/java4shell/vulnerable"));
        assertTrue(html.contains("/java4shell/mitigated"));
        assertTrue(html.contains("Java4Shell"));
        assertTrue(html.contains(System.getProperty("os.arch")));
    }
}
