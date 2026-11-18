package com.owasp.demo;

import com.owasp.demo.config.AppConfig;
import com.owasp.demo.db.Database;
import org.apache.catalina.Context;
import com.owasp.demo.interceptor.ConsoleAuthFilter;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.valves.AccessLogValve;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;
import org.h2.server.web.JakartaWebServlet;
import org.apache.tomcat.util.http.Rfc6265CookieProcessor;

import java.io.File;

public class Main {

    public static void main(String[] args) throws Exception {
        AppConfig cfg = AppConfig.get();
        Database.init();
        Runtime.getRuntime().addShutdownHook(new Thread(Database::shutdown));

        Tomcat tomcat = new Tomcat();
        tomcat.setPort(cfg.getServerPort());
        Connector connector = tomcat.getConnector();
        connector.setProperty("address", cfg.getString("server.bind_address"));
        if ("true".equals(cfg.getString("server.virtual_threads"))) {
            // Each request runs on its own virtual thread instead of a pooled platform thread.
            if (!connector.setProperty("useVirtualThreads", "true")) {
                throw new IllegalStateException("This Tomcat does not accept useVirtualThreads");
            }
        }

        if ("true".equals(cfg.getString("access_log.enabled"))) {
            // One line per request, written straight to the file. The pattern has no headers or cookies.
            AccessLogValve accessLog = new AccessLogValve();
            accessLog.setDirectory(new File(cfg.getString("access_log.directory")).getAbsolutePath());
            accessLog.setPrefix(cfg.getString("access_log.prefix"));
            accessLog.setSuffix(cfg.getString("access_log.suffix"));
            accessLog.setPattern(cfg.getString("access_log.pattern"));
            accessLog.setBuffered(false);
            tomcat.getHost().getPipeline().addValve(accessLog);
        }

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

        if ("true".equals(cfg.getString("h2_console.enabled"))) {
            String base = cfg.getString("h2_console.path");
            Tomcat.addServlet(ctx, "h2Console", new JakartaWebServlet());
            ctx.addServletMappingDecoded(base + "/*", "h2Console");
            FilterDef def = new FilterDef();
            def.setFilterName("h2ConsoleAuth");
            def.setFilter(new ConsoleAuthFilter());
            ctx.addFilterDef(def);
            FilterMap map = new FilterMap();
            map.setFilterName("h2ConsoleAuth");
            map.addURLPattern(base + "/*");
            ctx.addFilterMap(map);
        }

        tomcat.start();
        System.out.println(cfg.getAppName() + " running at http://localhost:" + cfg.getServerPort() + ("true".equals(cfg.getString("server.virtual_threads")) ? " (virtual threads)" : ""));
        if ("true".equals(cfg.getString("access_log.enabled"))) {
            System.out.println("Access log: " + new File(cfg.getString("access_log.directory")).getAbsolutePath()
                + File.separator + cfg.getString("access_log.prefix") + ".<date>" + cfg.getString("access_log.suffix"));
        }
        if ("true".equals(cfg.getString("h2_console.enabled"))) {
            System.out.println("H2 console at http://localhost:" + cfg.getServerPort() + cfg.getString("h2_console.path")
                + "  JDBC URL: " + cfg.getDbUrl() + "  user: " + cfg.getDbUsername());
        }
        tomcat.getServer().await();
    }
}
