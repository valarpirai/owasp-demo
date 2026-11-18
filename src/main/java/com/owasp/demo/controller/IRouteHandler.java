package com.owasp.demo.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public interface IRouteHandler {
    void handle(HttpServletRequest req, HttpServletResponse res) throws IOException;
}
