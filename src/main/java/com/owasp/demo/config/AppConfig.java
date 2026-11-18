package com.owasp.demo.config;

import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.util.List;
import java.util.Map;

public class AppConfig {

    private static final AppConfig INSTANCE = new AppConfig();

    private final int serverPort;
    private final String dbUrl;
    private final String dbUsername;
    private final String dbPassword;
    private final String appName;
    private final String adminUsername;
    private final String adminPassword;
    private final String adminRole;
    private final String seedUsername;
    private final String seedPassword;
    private final String seedRole;
    private final List<String> ssrfAllowlist;
    private final int maxFailedAttempts;
    private final int lockoutMinutes;
    private final int otpMaxAttempts;
    private final String hmacSecret;

    @SuppressWarnings("unchecked")
    private AppConfig() {
        Yaml yaml = new Yaml();
        InputStream in = getClass().getClassLoader().getResourceAsStream("application.yml");
        Map<String, Object> cfg = yaml.load(in);

        Map<String, Object> server = (Map<String, Object>) cfg.get("server");
        serverPort = (int) server.get("port");

        Map<String, Object> db = (Map<String, Object>) cfg.get("database");
        dbUrl = (String) db.get("url");
        dbUsername = (String) db.get("username");
        dbPassword = (String) db.get("password");

        Map<String, Object> app = (Map<String, Object>) cfg.get("app");
        appName = (String) app.get("name");

        Map<String, Object> seed = (Map<String, Object>) app.get("seed");
        Map<String, Object> admin = (Map<String, Object>) seed.get("admin");
        adminUsername = (String) admin.get("username");
        adminPassword = (String) admin.get("password");
        adminRole = (String) admin.get("role");

        Map<String, Object> user = (Map<String, Object>) seed.get("user");
        seedUsername = (String) user.get("username");
        seedPassword = (String) user.get("password");
        seedRole = (String) user.get("role");

        ssrfAllowlist = cfg.get("ssrf") != null
            ? (List<String>) ((Map<String, Object>) cfg.get("ssrf")).get("allowlist")
            : List.of();

        Map<String, Object> auth = (Map<String, Object>) cfg.get("auth");
        maxFailedAttempts = (int) auth.get("max_failed_attempts");
        lockoutMinutes = (int) auth.get("lockout_minutes");

        Map<String, Object> otp = (Map<String, Object>) cfg.get("otp");
        otpMaxAttempts = (int) otp.get("max_attempts");

        Map<String, Object> integrity = (Map<String, Object>) cfg.get("integrity");
        hmacSecret = (String) integrity.get("hmac_secret");
    }

    public static AppConfig get() { return INSTANCE; }

    public int getServerPort()        { return serverPort; }
    public String getDbUrl()          { return dbUrl; }
    public String getDbUsername()     { return dbUsername; }
    public String getDbPassword()     { return dbPassword; }
    public String getAppName()        { return appName; }
    public String getAdminUsername()  { return adminUsername; }
    public String getAdminPassword()  { return adminPassword; }
    public String getAdminRole()      { return adminRole; }
    public String getSeedUsername()   { return seedUsername; }
    public String getSeedPassword()   { return seedPassword; }
    public String getSeedRole()       { return seedRole; }
    public List<String> getSsrfAllowlist()  { return ssrfAllowlist; }
    public int getMaxFailedAttempts() { return maxFailedAttempts; }
    public int getLockoutMinutes()    { return lockoutMinutes; }
    public int getOtpMaxAttempts()    { return otpMaxAttempts; }
    public String getHmacSecret()     { return hmacSecret; }
}
