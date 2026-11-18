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
}
