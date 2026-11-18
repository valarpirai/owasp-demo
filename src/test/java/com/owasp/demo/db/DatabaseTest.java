package com.owasp.demo.db;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.*;

class DatabaseTest {

    @BeforeAll
    static void setupDb() throws SQLException {
        Database.init();
    }

    @Test
    void init_createsSessionsTableWithExpectedColumns() throws Exception {
        try (Connection conn = Database.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(
                 "SELECT session_id, user_id, created_at, last_seen_at, expires_at FROM sessions")) {
            assertNotNull(rs.getMetaData());
        }
    }

    @Test
    void getConnection_returnsPooledConnection() throws Exception {
        try (Connection conn = Database.getConnection()) {
            assertTrue(conn.getClass().getName().contains("Hikari"), "connection must come from the pool");
            assertTrue(Database.activeConnections() >= 1);
        }
        assertEquals(0, Database.activeConnections(), "closing returns the connection");
    }

    @Test
    void poolSizeComesFromConfig() {
        assertEquals(10, Database.maxConnections());
    }

    @Test
    void jooqQueriesReturnTheirConnections() throws Exception {
        var users = new com.owasp.demo.repository.UserRepository();
        for (int i = 0; i < 50; i++) {
            users.findAll();
            users.findByUsernameSafe("admin");
        }
        assertEquals(0, Database.activeConnections(), "jOOQ must not keep connections checked out");
    }

    @Test
    void manyParallelQueriesShareTheSmallPool() throws Exception {
        var users = new com.owasp.demo.repository.UserRepository();
        try (var exec = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
            var tasks = new java.util.ArrayList<java.util.concurrent.Future<Integer>>();
            for (int i = 0; i < 200; i++) tasks.add(exec.submit(() -> users.findAll().size()));
            for (var t : tasks) assertEquals(2, t.get());
        }
        assertEquals(0, Database.activeConnections());
    }
}
