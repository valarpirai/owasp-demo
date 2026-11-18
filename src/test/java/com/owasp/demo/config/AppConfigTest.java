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
}
