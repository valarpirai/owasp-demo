package com.owasp.demo;

import com.owasp.demo.interceptor.AuthInterceptor;
import com.owasp.demo.interceptor.Interceptor;
import com.owasp.demo.interceptor.RouteInterceptor;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public class AppServlet extends HttpServlet {

    private final Map<String, RouteRegistry.Route> routes;
    private final List<Interceptor> interceptors;

    public AppServlet() {
        AuthInterceptor authInterceptor = new AuthInterceptor();
        interceptors = List.of(new RouteInterceptor(authInterceptor), authInterceptor);
        routes = RouteRegistry.scan("com.owasp.demo.controller");
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String path = req.getPathInfo();
        if (path == null || path.isEmpty()) path = "/";

        for (Interceptor i : interceptors) {
            if (!i.preHandle(req, res, path)) return;
        }

        RouteRegistry.Route route = routes.get(req.getMethod() + " " + path);

        if (route != null) {
            route.invoke(req, res);
            for (int i = interceptors.size() - 1; i >= 0; i--) {
                interceptors.get(i).afterHandle(req, res, path);
            }
        } else {
            res.setStatus(404);
            res.getWriter().write("<h1>404 Not Found</h1><p>Path: " + path + "</p>");
        }
    }
}
