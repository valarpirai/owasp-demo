package com.owasp.demo;

import com.owasp.demo.repository.SessionRepository;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;

/**
 * Deletes the sessions row when Tomcat ends a session. This covers logout
 * and idle timeout, so the table never keeps rows for dead sessions.
 */
public class SessionCleanupListener implements HttpSessionListener {

    private final SessionRepository sessions = new SessionRepository();

    @Override
    public void sessionDestroyed(HttpSessionEvent event) {
        try {
            sessions.delete(event.getSession().getId());
        } catch (Exception ignored) {
            // Nothing to recover. The session is already gone.
        }
    }
}
