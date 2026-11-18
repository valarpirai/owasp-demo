package com.owasp.demo.repository;

import com.owasp.demo.db.Database;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.*;

class SessionRepositoryTest {

    private static SessionRepository repo;
    private static int adminId;

    @BeforeAll
    static void setup() throws SQLException {
        Database.init();
        repo = new SessionRepository();
        adminId = new UserRepository().findByUsernameSafe("admin").getFirst().id();
    }

    @Test
    void create_thenExists_thenDelete() throws SQLException {
        repo.create("abc123", adminId, 30);
        assertTrue(repo.exists("abc123"));
        repo.delete("abc123");
        assertFalse(repo.exists("abc123"));
    }

    @Test
    void create_doesNotStoreRawSessionId() throws SQLException {
        repo.create("raw-id-xyz", adminId, 30);
        Object stored = com.owasp.demo.db.JooqProvider.ctx()
            .fetchValue("SELECT COUNT(*) FROM sessions WHERE session_id = 'raw-id-xyz'");
        assertEquals(0L, ((Number) stored).longValue());
        repo.delete("raw-id-xyz");
    }

    @Test
    void touch_pushesExpiryForward() throws SQLException {
        repo.create("touch-id", adminId, 1);
        Object before = com.owasp.demo.db.JooqProvider.ctx()
            .fetchValue("SELECT expires_at FROM sessions WHERE session_id = '" + sha("touch-id") + "'");
        repo.touch("touch-id", 5);
        Object after = com.owasp.demo.db.JooqProvider.ctx()
            .fetchValue("SELECT expires_at FROM sessions WHERE session_id = '" + sha("touch-id") + "'");
        assertTrue(((java.sql.Timestamp) after).after((java.sql.Timestamp) before));
        repo.delete("touch-id");
    }

    private static String sha(String v) throws SQLException {
        try {
            return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                .digest(v.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
