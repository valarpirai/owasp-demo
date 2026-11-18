package com.owasp.demo.controller;

import com.owasp.demo.model.User;
import com.owasp.demo.config.AppConfig;
import com.owasp.demo.repository.SessionRepository;
import com.owasp.demo.repository.UserRepository;
import com.owasp.demo.view.TemplateEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

public class LoginHandler implements IRouteHandler {

    private final UserRepository userRepository = new UserRepository();
    private final SessionRepository sessionRepository = new SessionRepository();

    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String path = req.getPathInfo();

        if ("GET".equals(req.getMethod()) && "/logout".equals(path)) {
            HttpSession session = req.getSession(false);
            if (session != null) {
                try {
                    sessionRepository.delete(session.getId());
                } catch (Exception ignored) {
                    // The cookie is invalidated below either way.
                }
                session.invalidate();
            }
            res.sendRedirect("/login");
            return;
        }

        if ("POST".equals(req.getMethod())) {
            handlePost(req, res);
            return;
        }

        HttpSession existing = req.getSession(false);
        if (existing != null && existing.getAttribute("user") != null) {
            // Another tab already logged in. Same cookie, same session.
            res.sendRedirect("/");
            return;
        }
        renderLogin(res, null);
    }

    private void handlePost(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String username = req.getParameter("username");
        String password = req.getParameter("password");

        try {
            Optional<User> user = userRepository.findByUsernameAndPasswordSafe(username, password);
            if (user.isPresent()) {
                HttpSession session = req.getSession(false);
                if (session != null) {
                    // New ID after login stops session fixation.
                    req.changeSessionId();
                } else {
                    session = req.getSession(true);
                }
                session.setAttribute("user", user.get().username());
                session.setAttribute("role", user.get().role());
                sessionRepository.create(session.getId(), user.get().id(),
                    AppConfig.get().getInt("session.timeout_minutes"));
                res.sendRedirect("/");
            } else {
                renderLogin(res, "Invalid username or password.");
            }
        } catch (Exception e) {
            renderLogin(res, "Login error: " + TemplateEngine.escape(e.getMessage()));
        }
    }

    /**
     * Builds one list row per user. Each row has a button that fills the login form.
     * Passwords are shown on purpose. This is a local demo.
     *
     * @return list items HTML, or an empty string if the users cannot be read
     */
    private String userListHtml() {
        try {
            StringBuilder rows = new StringBuilder();
            for (User u : userRepository.findAll()) {
                rows.append("""
                    <li class="flex items-center justify-between text-sm">
                      <span><strong>%s</strong> <span class="text-gray-400">%s</span></span>
                      <button type="button" data-user="%s" data-pass="%s"
                        onclick="document.querySelector('[name=username]').value=this.dataset.user;document.querySelector('[name=password]').value=this.dataset.pass"
                        class="border border-gray-300 rounded px-2 py-1 text-xs text-gray-600 hover:bg-gray-50">Use</button>
                    </li>
                    """.formatted(
                        TemplateEngine.escape(u.username()), TemplateEngine.escape(u.role()),
                        TemplateEngine.escape(u.username()), TemplateEngine.escape(demoPassword(u.username()))));
            }
            return rows.toString();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * The database holds only hashes, so the demo buttons read the seed passwords from config.
     *
     * @param username a listed user
     * @return the seed password, or an empty string for any other user
     */
    private String demoPassword(String username) {
        AppConfig cfg = AppConfig.get();
        if (username.equals(cfg.getAdminUsername())) return cfg.getAdminPassword();
        if (username.equals(cfg.getSeedUsername())) return cfg.getSeedPassword();
        return "";
    }

    private void renderLogin(HttpServletResponse res, String error) throws IOException {
        String errorHtml = error != null
            ? "<div class=\"mb-4 p-3 bg-red-100 text-red-700 rounded text-sm\">%s</div>".formatted(error)
            : "";

        String content = TemplateEngine.render("login.html", Map.of(
            "error", errorHtml,
            "users", userListHtml()
        ));

        res.getWriter().write(TemplateEngine.page("Login", content, false));
    }
}
