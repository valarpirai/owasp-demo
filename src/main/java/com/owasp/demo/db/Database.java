package com.owasp.demo.db;

import com.owasp.demo.config.AppConfig;
import com.owasp.demo.util.PasswordHasher;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class Database {

    public static Connection getConnection() throws SQLException {
        AppConfig cfg = AppConfig.get();
        return DriverManager.getConnection(cfg.getDbUrl(), cfg.getDbUsername(), cfg.getDbPassword());
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
