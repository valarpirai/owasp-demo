package com.owasp.demo;

import com.owasp.demo.config.AppConfig;
import com.owasp.demo.db.Database;
import org.apache.catalina.Context;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.http.Rfc6265CookieProcessor;

import java.io.File;

public class Main {

    private static final int SESSION_TIMEOUT_MINUTES = 30;

    public static void main(String[] args) throws Exception {
        AppConfig cfg = AppConfig.get();
        Database.init();

        Tomcat tomcat = new Tomcat();
        tomcat.setPort(cfg.getServerPort());
        tomcat.getConnector().setProperty("address", "127.0.0.1");

        Context ctx = tomcat.addContext("", new File(".").getAbsolutePath());
        ctx.setUseHttpOnly(true);
        ctx.setSessionTimeout(SESSION_TIMEOUT_MINUTES);
        Rfc6265CookieProcessor cookies = new Rfc6265CookieProcessor();
        cookies.setSameSiteCookies("Lax");
        ctx.setCookieProcessor(cookies);
        Tomcat.addServlet(ctx, "appServlet", new AppServlet());
        ctx.addServletMappingDecoded("/*", "appServlet");

        tomcat.start();
        System.out.println(cfg.getAppName() + " running at http://localhost:" + cfg.getServerPort());
        tomcat.getServer().await();
    }
}
