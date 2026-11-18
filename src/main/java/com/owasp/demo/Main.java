package com.owasp.demo;

import com.owasp.demo.config.AppConfig;
import com.owasp.demo.db.Database;
import org.apache.catalina.Context;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.http.Rfc6265CookieProcessor;

import java.io.File;

public class Main {

    public static void main(String[] args) throws Exception {
        AppConfig cfg = AppConfig.get();
        Database.init();

        Tomcat tomcat = new Tomcat();
        tomcat.setPort(cfg.getServerPort());
        tomcat.getConnector().setProperty("address", cfg.getString("server.bind_address"));

        Context ctx = tomcat.addContext("", new File(".").getAbsolutePath());
        ctx.addApplicationListener(SessionCleanupListener.class.getName());
        ctx.setSessionCookieName(cfg.getString("session.cookie_name"));
        ctx.setUseHttpOnly(true);
        ctx.setSessionTimeout(cfg.getInt("session.timeout_minutes"));
        Rfc6265CookieProcessor cookies = new Rfc6265CookieProcessor();
        cookies.setSameSiteCookies(cfg.getString("session.same_site"));
        ctx.setCookieProcessor(cookies);
        Tomcat.addServlet(ctx, "appServlet", new AppServlet());
        ctx.addServletMappingDecoded("/*", "appServlet");

        tomcat.start();
        System.out.println(cfg.getAppName() + " running at http://localhost:" + cfg.getServerPort());
        tomcat.getServer().await();
    }
}
