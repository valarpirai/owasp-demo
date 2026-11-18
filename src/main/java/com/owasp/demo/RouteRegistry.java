package com.owasp.demo;

import com.owasp.demo.controller.Controller;
import com.owasp.demo.controller.GetMapping;
import com.owasp.demo.controller.PostMapping;
import io.github.classgraph.ClassGraph;
import io.github.classgraph.ClassInfo;
import io.github.classgraph.ScanResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 * Builds the route table from annotations. {@link #scan(String)} finds every
 * {@link Controller} under a package. {@link #of(Object)} reads one instance.
 * Keys look like {@code "GET /xss"}.
 */
public final class RouteRegistry {

    /** One mapped method on one controller instance. */
    public record Route(Object controller, Method method) {

        /**
         * Calls the mapped method. Checked and runtime errors from the handler pass through unchanged.
         *
         * @param req the request
         * @param res the response
         * @throws IOException if the handler throws it
         */
        public void invoke(HttpServletRequest req, HttpServletResponse res) throws IOException {
            try {
                method.invoke(controller, req, res);
            } catch (InvocationTargetException e) {
                Throwable cause = e.getCause();
                if (cause instanceof IOException io) throw io;
                if (cause instanceof RuntimeException re) throw re;
                if (cause instanceof Error err) throw err;
                throw new IllegalStateException(cause);
            } catch (IllegalAccessException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private RouteRegistry() {
    }

    /**
     * Scans a package tree for {@link Controller} classes and registers their routes.
     *
     * @param basePackage the package to scan, e.g. {@code com.owasp.demo.controller}
     * @return the route table keyed by {@code "METHOD /path"}
     * @throws IllegalStateException on a duplicate route or a controller that cannot be created
     */
    public static Map<String, Route> scan(String basePackage) {
        Map<String, Route> routes = new HashMap<>();
        try (ScanResult scan = new ClassGraph()
                .acceptPackages(basePackage)
                .enableClassInfo()
                .enableAnnotationInfo()
                .scan()) {
            for (ClassInfo info : scan.getClassesWithAnnotation(Controller.class.getName())) {
                try {
                    register(routes, Class.forName(info.getName()).getDeclaredConstructor().newInstance());
                } catch (ReflectiveOperationException e) {
                    throw new IllegalStateException("Cannot create controller " + info.getName(), e);
                }
            }
        }
        return routes;
    }

    /**
     * Reads the routes of one controller instance.
     *
     * @param controller the controller
     * @return the route table keyed by {@code "METHOD /path"}
     */
    public static Map<String, Route> of(Object controller) {
        Map<String, Route> routes = new HashMap<>();
        register(routes, controller);
        return routes;
    }

    private static void register(Map<String, Route> routes, Object controller) {
        for (Method m : controller.getClass().getDeclaredMethods()) {
            GetMapping get = m.getAnnotation(GetMapping.class);
            PostMapping post = m.getAnnotation(PostMapping.class);
            if (get != null) add(routes, "GET " + get.value(), controller, m);
            if (post != null) add(routes, "POST " + post.value(), controller, m);
        }
    }

    private static void add(Map<String, Route> routes, String key, Object controller, Method m) {
        if (m.getParameterCount() != 2
                || m.getParameterTypes()[0] != HttpServletRequest.class
                || m.getParameterTypes()[1] != HttpServletResponse.class) {
            throw new IllegalStateException("Route method must take (HttpServletRequest, HttpServletResponse): " + m);
        }
        m.setAccessible(true);
        if (routes.put(key, new Route(controller, m)) != null) {
            throw new IllegalStateException("Duplicate route " + key);
        }
    }
}
