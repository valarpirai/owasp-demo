package com.owasp.demo;

import com.owasp.demo.controller.*;
import com.owasp.demo.interceptor.AuthInterceptor;
import com.owasp.demo.interceptor.Interceptor;
import com.owasp.demo.interceptor.RouteInterceptor;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AppServlet extends HttpServlet {

    private final Map<String, IRouteHandler> routes = new HashMap<>();
    private final List<Interceptor> interceptors;

    public AppServlet() {
        AuthInterceptor authInterceptor = new AuthInterceptor();
        interceptors = List.of(new RouteInterceptor(authInterceptor), authInterceptor);

        LoginHandler login = new LoginHandler();
        routes.put("GET /", new IndexHandler());
        routes.put("GET /login", login);
        routes.put("POST /login", login);
        routes.put("GET /logout", login);

        SqlInjectionHandler sqli = new SqlInjectionHandler();
        routes.put("GET /sqli", sqli);
        routes.put("POST /sqli/vulnerable", sqli);
        routes.put("POST /sqli/mitigated", sqli);

        XssHandler xss = new XssHandler();
        routes.put("GET /xss", xss);
        routes.put("POST /xss/vulnerable", xss);
        routes.put("POST /xss/mitigated", xss);

        BrokenAccessHandler bac = new BrokenAccessHandler();
        routes.put("GET /bac", bac);
        routes.put("GET /bac/vulnerable", bac);
        routes.put("GET /bac/mitigated", bac);

        CryptoFailuresHandler crypto = new CryptoFailuresHandler();
        routes.put("GET /crypto", crypto);
        routes.put("POST /crypto/vulnerable", crypto);
        routes.put("POST /crypto/mitigated", crypto);

        InsecureDesignHandler design = new InsecureDesignHandler();
        routes.put("GET /insecure-design", design);
        routes.put("POST /insecure-design/vulnerable", design);
        routes.put("POST /insecure-design/mitigated", design);

        SecurityMisconfigHandler misconfig = new SecurityMisconfigHandler();
        routes.put("GET /misconfig", misconfig);
        routes.put("GET /misconfig/vulnerable", misconfig);
        routes.put("GET /misconfig/mitigated", misconfig);

        VulnerableComponentsHandler vulnComp = new VulnerableComponentsHandler();
        routes.put("GET /vuln-components", vulnComp);

        AuthFailuresHandler auth = new AuthFailuresHandler();
        routes.put("GET /auth-failures", auth);
        routes.put("POST /auth-failures/vulnerable", auth);
        routes.put("POST /auth-failures/mitigated", auth);

        DataIntegrityHandler integrity = new DataIntegrityHandler();
        routes.put("GET /integrity", integrity);
        routes.put("POST /integrity/vulnerable", integrity);
        routes.put("POST /integrity/mitigated", integrity);

        LoggingMonitoringHandler logging = new LoggingMonitoringHandler();
        routes.put("GET /logging", logging);
        routes.put("POST /logging/vulnerable", logging);
        routes.put("POST /logging/mitigated", logging);

        SsrfHandler ssrf = new SsrfHandler();
        routes.put("GET /ssrf", ssrf);
        routes.put("POST /ssrf/vulnerable", ssrf);
        routes.put("POST /ssrf/mitigated", ssrf);

        RceHandler rce = new RceHandler();
        routes.put("GET /rce", rce);
        routes.put("POST /rce/vulnerable", rce);
        routes.put("POST /rce/mitigated", rce);

        CsrfHandler csrf = new CsrfHandler();
        routes.put("GET /csrf", csrf);
        routes.put("GET /csrf/attack", csrf);
        routes.put("POST /csrf/vulnerable", csrf);
        routes.put("POST /csrf/mitigated", csrf);

        DbBrowserHandler dbBrowser = new DbBrowserHandler();
        routes.put("GET /db-browser", dbBrowser);
        routes.put("GET /db-browser/table", dbBrowser);
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String path = req.getPathInfo();
        if (path == null || path.isEmpty()) path = "/";

        for (Interceptor i : interceptors) {
            if (!i.preHandle(req, res, path)) return;
        }

        IRouteHandler handler = routes.get(req.getMethod() + " " + path);

        if (handler != null) {
            handler.handle(req, res);
            for (int i = interceptors.size() - 1; i >= 0; i--) {
                interceptors.get(i).afterHandle(req, res, path);
            }
        } else {
            res.setStatus(404);
            res.getWriter().write("<h1>404 Not Found</h1><p>Path: " + path + "</p>");
        }
    }
}
