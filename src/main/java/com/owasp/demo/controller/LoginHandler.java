package com.owasp.demo.controller;

import com.owasp.demo.config.AppConfig;
import com.owasp.demo.model.User;
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

    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String path = req.getServletPath();

        if ("GET".equals(req.getMethod()) && "/logout".equals(path)) {
            HttpSession session = req.getSession(false);
            if (session != null) session.invalidate();
            res.sendRedirect("/login");
            return;
        }

        if ("POST".equals(req.getMethod())) {
            handlePost(req, res);
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
                HttpSession session = req.getSession(true);
                session.setAttribute("user", user.get().username());
                session.setAttribute("role", user.get().role());
                res.sendRedirect("/");
            } else {
                renderLogin(res, "Invalid username or password.");
            }
        } catch (Exception e) {
            renderLogin(res, "Login error: " + TemplateEngine.escape(e.getMessage()));
        }
    }

    private void renderLogin(HttpServletResponse res, String error) throws IOException {
        AppConfig cfg = AppConfig.get();
        String errorHtml = error != null
            ? "<div class=\"mb-4 p-3 bg-red-100 text-red-700 rounded text-sm\">%s</div>".formatted(error)
            : "";

        String content = TemplateEngine.render("login.html", Map.of(
            "error", errorHtml,
            "hint_user", cfg.getAdminUsername(),
            "hint_pass", cfg.getAdminPassword()
        ));

        res.getWriter().write(TemplateEngine.page("Login", content, false));
    }
}
