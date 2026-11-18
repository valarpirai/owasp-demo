package com.owasp.demo.controller;

import com.owasp.demo.RouteRegistry;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/** Test helper. Sends a mocked request to the controller route that matches its method and path. */
final class TestRoutes {

    private TestRoutes() {
    }

    /**
     * @param controller the controller under test
     * @param req a request mock with method and path info set
     * @param res a response mock
     * @throws IllegalStateException if no route matches
     */
    static void call(Object controller, HttpServletRequest req, HttpServletResponse res) throws IOException {
        String key = req.getMethod() + " " + req.getPathInfo();
        RouteRegistry.Route route = RouteRegistry.of(controller).get(key);
        if (route == null) throw new IllegalStateException("No route for " + key);
        route.invoke(req, res);
    }
}
