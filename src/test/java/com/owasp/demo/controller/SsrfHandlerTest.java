package com.owasp.demo.controller;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SsrfHandlerTest {

    // --- demoSafetyBlock ---

    @Test
    void safetyBlock_fileScheme_blocked() {
        String result = SsrfHandler.demoSafetyBlock("file:///etc/passwd");
        assertNotNull(result, "file:// must be blocked");
        assertTrue(result.contains("DEMO SAFETY BLOCK"));
        assertTrue(result.contains("file"));
    }

    @Test
    void safetyBlock_loopback_blocked() {
        String result = SsrfHandler.demoSafetyBlock("http://localhost/secret");
        assertNotNull(result, "loopback must be blocked");
        assertTrue(result.contains("DEMO SAFETY BLOCK"));
    }

    @Test
    void safetyBlock_loopbackIp_blocked() {
        String result = SsrfHandler.demoSafetyBlock("http://127.0.0.1:8090/admin");
        assertNotNull(result, "127.0.0.1 must be blocked");
    }

    @Test
    void safetyBlock_privateRange_blocked() {
        String result = SsrfHandler.demoSafetyBlock("http://192.168.1.1/");
        assertNotNull(result, "private IP must be blocked");
    }

    @Test
    void safetyBlock_cloudMetadata_blocked() {
        String result = SsrfHandler.demoSafetyBlock("http://169.254.169.254/latest/meta-data/");
        assertNotNull(result, "link-local cloud metadata must be blocked");
    }

    @Test
    void safetyBlock_publicUrl_allowed() {
        String result = SsrfHandler.demoSafetyBlock("https://httpbin.org/get");
        assertNull(result, "public HTTPS URL should not be blocked");
    }

    // --- isHostAllowed ---

    @Test
    void isHostAllowed_exactMatch_allowed() {
        List<String> allowlist = List.of("https://httpbin.org", "https://jsonplaceholder.typicode.com");
        assertTrue(SsrfHandler.isHostAllowed("https://httpbin.org/get", allowlist));
    }

    @Test
    void isHostAllowed_subdomain_blocked() {
        List<String> allowlist = List.of("https://httpbin.org");
        assertFalse(SsrfHandler.isHostAllowed("https://httpbin.org.evil.com/attack", allowlist),
            "Subdomain spoofing must not pass allowlist");
    }

    @Test
    void isHostAllowed_differentPath_allowed() {
        List<String> allowlist = List.of("https://httpbin.org");
        assertTrue(SsrfHandler.isHostAllowed("https://httpbin.org/anything/test", allowlist));
    }

    @Test
    void isHostAllowed_notInList_blocked() {
        List<String> allowlist = List.of("https://httpbin.org");
        assertFalse(SsrfHandler.isHostAllowed("https://example.com/page", allowlist));
    }

    @Test
    void isHostAllowed_emptyList_blocked() {
        assertFalse(SsrfHandler.isHostAllowed("https://httpbin.org/get", List.of()));
    }
}
