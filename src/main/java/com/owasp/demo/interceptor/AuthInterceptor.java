package com.owasp.demo.interceptor;

import com.owasp.demo.config.AppConfig;
import com.owasp.demo.repository.SessionRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.util.Set;

/**
 * Sends anonymous users to /login. For logged-in users it moves the
 * sessions row expiry forward on every request.
 */
public class AuthInterceptor implements Interceptor {

    private final Set<String> publicPaths = Set.copyOf(AppConfig.get().getStringList("security.public_paths"));
    private final SessionRepository sessions = new SessionRepository();

    /**
     * @param path the request path
     * @return true if the path needs no login
     */
    public boolean isPublic(String path) {
        return publicPaths.contains(path);
    }

    @Override
    public boolean preHandle(HttpServletRequest req, HttpServletResponse res, String path) throws IOException {
        if (isPublic(path)) return true;

        HttpSession session = req.getSession(false);
        if (session == null || session.getAttribute("user") == null) {
            res.sendRedirect("/login");
            return false;
        }
        touch(session);
        return true;
    }

    /**
     * Slides the session row's expiry forward. A failed write never breaks the request.
     *
     * @param session the logged-in session
     */
    private void touch(HttpSession session) {
        try {
            sessions.touch(session.getId(), AppConfig.get().getInt("session.timeout_minutes"));
        } catch (Exception e) {
            // The Tomcat session still enforces the timeout.
        }
    }
}
