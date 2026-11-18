package com.owasp.demo.interceptor;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Puts the H2 console behind the app's login. A browser session or HTTP Basic
 * auth is accepted, the same as for every other route.
 */
public class ConsoleAuthFilter implements Filter {

    private final AuthInterceptor auth = new AuthInterceptor();

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        if (auth.preHandle(request, response, "/h2-console")) {
            chain.doFilter(req, res);
        }
    }
}
