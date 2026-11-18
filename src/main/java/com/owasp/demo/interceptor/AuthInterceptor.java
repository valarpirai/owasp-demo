package com.owasp.demo.interceptor;

import com.owasp.demo.config.AppConfig;
import com.owasp.demo.model.User;
import com.owasp.demo.repository.SessionRepository;
import com.owasp.demo.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;

/**
 * Lets logged-in users through. Anonymous browsers go to /login. A request with
 * an Authorization: Basic header is checked against the users table, so curl
 * can call any route with {@code -u user:password}. Bad credentials get a 401.
 * Basic auth opens a short-lived session and writes no sessions row.
 */
public class AuthInterceptor implements Interceptor {

    private final Set<String> publicPaths = Set.copyOf(AppConfig.get().getStringList("security.public_paths"));
    private final SessionRepository sessions = new SessionRepository();
    private final UserRepository users = new UserRepository();

    private static final int BASIC_SESSION_SECONDS = 60;

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
        if (session != null && session.getAttribute("user") != null) {
            touch(session);
            return true;
        }

        String header = req.getHeader("Authorization");
        if (header != null && header.regionMatches(true, 0, "Basic ", 0, 6)) {
            Optional<User> user = checkBasic(header.substring(6).trim());
            if (user.isEmpty()) {
                res.setStatus(401);
                res.setHeader("WWW-Authenticate", "Basic realm=\"owasp-demo\", charset=\"UTF-8\"");
                return false;
            }
            HttpSession basic = req.getSession(true);
            basic.setAttribute("user", user.get().username());
            basic.setAttribute("role", user.get().role());
            basic.setMaxInactiveInterval(BASIC_SESSION_SECONDS);
            return true;
        }

        res.sendRedirect("/login");
        return false;
    }

    /**
     * Decodes a Basic credential and checks it against the users table.
     *
     * @param encoded the Base64 text after "Basic "
     * @return the user, or empty if the text or the credentials are bad
     */
    private Optional<User> checkBasic(String encoded) {
        try {
            String decoded = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            if (colon < 0) return Optional.empty();
            return users.findByUsernameAndPasswordSafe(decoded.substring(0, colon), decoded.substring(colon + 1));
        } catch (Exception e) {
            return Optional.empty();
        }
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
