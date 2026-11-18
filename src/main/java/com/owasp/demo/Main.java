package com.owasp.demo;

import com.owasp.demo.config.AppConfig;
import com.owasp.demo.db.Database;
import org.apache.catalina.Context;
import org.apache.catalina.startup.Tomcat;

import java.io.File;

public class Main {

    public static void main(String[] args) throws Exception {
        AppConfig cfg = AppConfig.get();
        Database.init();

        Tomcat tomcat = new Tomcat();
        tomcat.setPort(cfg.getServerPort());
        tomcat.getConnector();

        Context ctx = tomcat.addContext("", new File(".").getAbsolutePath());
        Tomcat.addServlet(ctx, "appServlet", new AppServlet());
        ctx.addServletMappingDecoded("/*", "appServlet");

        tomcat.start();
        System.out.println(cfg.getAppName() + " running at http://localhost:" + cfg.getServerPort());
        tomcat.getServer().await();
    }
}
