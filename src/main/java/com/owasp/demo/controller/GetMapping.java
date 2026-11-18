package com.owasp.demo.controller;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Maps a controller method to a GET path. The method must take
 * {@code (HttpServletRequest, HttpServletResponse)}.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface GetMapping {
    /** The path as returned by {@code req.getPathInfo()}, e.g. {@code /xss}. */
    String value();
}
