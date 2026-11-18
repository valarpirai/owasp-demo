package com.owasp.demo.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasswordHasherTest {

    @Test
    void hashIsBcryptAndNotThePassword() {
        String h = PasswordHasher.hash("s3cret");
        assertTrue(h.startsWith("$2a$10$"), "cost 10 from config");
        assertEquals(60, h.length());
        assertFalse(h.contains("s3cret"));
    }

    @Test
    void sameSecretGivesDifferentHashes() {
        assertNotEquals(PasswordHasher.hash("s3cret"), PasswordHasher.hash("s3cret"));
    }

    @Test
    void verifyAcceptsRightAndRejectsWrong() {
        String h = PasswordHasher.hash("s3cret");
        assertTrue(PasswordHasher.verify("s3cret", h));
        assertFalse(PasswordHasher.verify("S3cret", h));
        assertFalse(PasswordHasher.verify("", h));
    }

    @Test
    void verifyIsFalseForNullOrNonBcryptValues() {
        assertFalse(PasswordHasher.verify(null, "x"));
        assertFalse(PasswordHasher.verify("a", null));
        assertFalse(PasswordHasher.verify("admin123", "admin123"), "a clear-text value never matches");
        assertFalse(PasswordHasher.verify("a", "0192023a7bbd73250516f069df18b500"), "an MD5 value never matches");
    }
}
