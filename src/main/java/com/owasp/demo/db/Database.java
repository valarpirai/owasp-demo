package com.owasp.demo.db;

import com.owasp.demo.config.AppConfig;
import com.owasp.demo.util.PasswordHasher;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class Database {

    /** Created on first use. The holder class makes that thread-safe without a lock. */
    private static final class Pool {
        static final HikariDataSource DS = create();

        private static HikariDataSource create() {
            AppConfig cfg = AppConfig.get();
            HikariConfig hc = new HikariConfig();
            hc.setPoolName(cfg.getString("database.pool.name"));
            hc.setJdbcUrl(cfg.getDbUrl());
            hc.setUsername(cfg.getDbUsername());
            hc.setPassword(cfg.getDbPassword());
            hc.setMaximumPoolSize(cfg.getInt("database.pool.max_size"));
            hc.setMinimumIdle(cfg.getInt("database.pool.min_idle"));
            hc.setConnectionTimeout(cfg.getInt("database.pool.connection_timeout_ms"));
            // Logs a warning with a stack trace if a connection is held too long. It finds missing close() calls.
            hc.setLeakDetectionThreshold(cfg.getInt("database.pool.leak_detection_ms"));
            return new HikariDataSource(hc);
        }
    }

    /**
     * Borrows a connection from the pool. Close it to give it back.
     *
     * @return a pooled connection
     */
    public static Connection getConnection() throws SQLException {
        return Pool.DS.getConnection();
    }

    /**
     * @return the pool, for libraries that borrow connections themselves
     */
    public static DataSource dataSource() {
        return Pool.DS;
    }

    /**
     * @return connections that are checked out right now
     */
    public static int activeConnections() {
        return Pool.DS.getHikariPoolMXBean().getActiveConnections();
    }

    /**
     * @return the most connections the pool will open
     */
    public static int maxConnections() {
        return Pool.DS.getMaximumPoolSize();
    }

    /** Closes the pool. Call once when the app stops. */
    public static void shutdown() {
        Pool.DS.close();
    }

    /**
     * Adds a user with a bcrypt hash of the password. An existing user is left as it is,
     * so repeated init calls do not re-hash.
     *
     * @param conn open connection
     * @param username login name
     * @param password clear-text seed password from application.yml
     * @param role user role
     */
    private static void seedUser(Connection conn, String username, String password, String role) throws SQLException {
        try (PreparedStatement exists = conn.prepareStatement("SELECT 1 FROM users WHERE username = ?")) {
            exists.setString(1, username);
            try (ResultSet rs = exists.executeQuery()) {
                if (rs.next()) return;
            }
        }
        try (PreparedStatement insert = conn.prepareStatement(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)")) {
            insert.setString(1, username);
            insert.setString(2, PasswordHasher.hash(password));
            insert.setString(3, role);
            insert.executeUpdate();
        }
    }

    public static void init() throws SQLException {
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    role VARCHAR(50) NOT NULL
                )
            """);

            stmt.execute("""
                CREATE TABLE IF NOT EXISTS products (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(200) NOT NULL,
                    price DECIMAL(10,2) NOT NULL,
                    description VARCHAR(500)
                )
            """);

            stmt.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    event VARCHAR(100) NOT NULL,
                    details VARCHAR(500)
                )
            """);

            stmt.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id VARCHAR(64) PRIMARY KEY,
                    user_id INT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """);

            AppConfig cfg = AppConfig.get();
            seedUser(conn, cfg.getAdminUsername(), cfg.getAdminPassword(), cfg.getAdminRole());
            seedUser(conn, cfg.getSeedUsername(), cfg.getSeedPassword(), cfg.getSeedRole());

            stmt.execute("""
                MERGE INTO products (id, name, price, description)
                KEY(id)
                VALUES (1, 'Widget A', 9.99, 'Standard widget'),
                       (2, 'Widget B', 19.99, 'Premium widget'),
                       (3, 'Secret Widget', 999.99, 'Admin-only product')
            """);
        }
    }
}
