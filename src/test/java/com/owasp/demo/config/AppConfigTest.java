package com.owasp.demo.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AppConfigTest {

    private final AppConfig cfg = AppConfig.get();

    @Test
    void serverPortIsLoaded() {
        assertEquals(8090, cfg.getServerPort());
    }

    @Test
    void databaseUrlIsLoaded() {
        assertTrue(cfg.getDbUrl().startsWith("jdbc:h2:mem:"));
    }

    @Test
    void adminCredentialsAreLoaded() {
        assertEquals("admin", cfg.getAdminUsername());
        assertNotNull(cfg.getAdminPassword());
        assertEquals("ADMIN", cfg.getAdminRole());
    }

    @Test
    void seedUserCredentialsAreLoaded() {
        assertEquals("user", cfg.getSeedUsername());
        assertEquals("USER", cfg.getSeedRole());
    }

    @Test
    void ssrfAllowlistIsLoaded() {
        assertFalse(cfg.getSsrfAllowlist().isEmpty());
    }

    @Test
    void authLockoutConfigIsLoaded() {
        assertTrue(cfg.getMaxFailedAttempts() > 0);
        assertTrue(cfg.getLockoutMinutes() > 0);
    }

    @Test
    void otpMaxAttemptsIsLoaded() {
        assertTrue(cfg.getOtpMaxAttempts() > 0);
    }

    @Test
    void genericLookupReadsNestedValues() {
        assertEquals(30, cfg.getInt("session.timeout_minutes"));
        assertEquals("Lax", cfg.getString("session.same_site"));
        assertTrue(cfg.getStringList("security.public_paths").contains("/login"));
        assertEquals("DENY", cfg.getStringMap("security.headers").get("X-Frame-Options"));
    }

    @Test
    void genericLookupThrowsForMissingKey() {
        assertThrows(IllegalStateException.class, () -> cfg.getString("no.such.key"));
    }
}
