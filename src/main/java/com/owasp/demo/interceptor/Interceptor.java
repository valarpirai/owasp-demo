package com.owasp.demo.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Runs before and after a route handler. {@code AppServlet} calls
 * {@code preHandle} in list order and {@code afterHandle} in reverse order.
 */
public interface Interceptor {

    /**
     * Runs before the handler.
     *
     * @param req the request
     * @param res the response
     * @param path the request path, never null
     * @return false to stop the request. The interceptor must have written the response.
     */
    boolean preHandle(HttpServletRequest req, HttpServletResponse res, String path) throws IOException;

    /**
     * Runs after the handler finished. Skipped when the request was stopped or had no route.
     *
     * @param req the request
     * @param res the response
     * @param path the request path, never null
     */
    default void afterHandle(HttpServletRequest req, HttpServletResponse res, String path) {}
}
