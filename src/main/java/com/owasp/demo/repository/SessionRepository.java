package com.owasp.demo.repository;

import com.owasp.demo.db.JooqProvider;
import org.jooq.DSLContext;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;

import static org.jooq.impl.DSL.field;
import static org.jooq.impl.DSL.table;

/**
 * Stores one row per login. The table keeps a SHA-256 hash of the session ID,
 * never the ID itself, so a leaked table cannot be replayed as a cookie.
 * Timestamps are UTC.
 */
public class SessionRepository {

    /**
     * Records a new session.
     *
     * @param sessionId the servlet session ID
     * @param userId the logged-in user's ID
     * @param ttlMinutes minutes until the row expires
     */
    public void create(String sessionId, int userId, int ttlMinutes) throws SQLException {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        DSLContext ctx = JooqProvider.ctx();
        ctx.insertInto(table("sessions"))
            .set(field("session_id"), hash(sessionId))
            .set(field("user_id"), userId)
            .set(field("created_at"), now)
            .set(field("last_seen_at"), now)
            .set(field("expires_at"), now.plusMinutes(ttlMinutes))
            .execute();
    }

    /**
     * Marks the session as active now and pushes its expiry forward.
     *
     * @param sessionId the servlet session ID
     * @param ttlMinutes minutes of inactivity before the row expires
     */
    public void touch(String sessionId, int ttlMinutes) throws SQLException {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        JooqProvider.ctx().update(table("sessions"))
            .set(field("last_seen_at"), now)
            .set(field("expires_at"), now.plusMinutes(ttlMinutes))
            .where(field("session_id").eq(hash(sessionId)))
            .execute();
    }

    /**
     * Removes a session row, for example on logout.
     *
     * @param sessionId the servlet session ID
     */
    public void delete(String sessionId) throws SQLException {
        JooqProvider.ctx().deleteFrom(table("sessions"))
            .where(field("session_id").eq(hash(sessionId)))
            .execute();
    }

    /**
     * @param sessionId the servlet session ID
     * @return true if a row exists for the ID
     */
    public boolean exists(String sessionId) throws SQLException {
        return JooqProvider.ctx().fetchExists(
            table("sessions"), field("session_id").eq(hash(sessionId)));
    }

    private static String hash(String sessionId) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(sessionId.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
