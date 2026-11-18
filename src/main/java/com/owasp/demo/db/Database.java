package com.owasp.demo.db;

import com.owasp.demo.config.AppConfig;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class Database {

    public static Connection getConnection() throws SQLException {
        AppConfig cfg = AppConfig.get();
        return DriverManager.getConnection(cfg.getDbUrl(), cfg.getDbUsername(), cfg.getDbPassword());
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
            stmt.execute("""
                MERGE INTO users (username, password, role)
                KEY(username)
                VALUES ('%s', '%s', '%s'),
                       ('%s', '%s', '%s')
            """.formatted(
                cfg.getAdminUsername(), cfg.getAdminPassword(), cfg.getAdminRole(),
                cfg.getSeedUsername(), cfg.getSeedPassword(), cfg.getSeedRole()
            ));

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
