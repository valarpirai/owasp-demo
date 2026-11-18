package com.owasp.demo.repository;

import com.owasp.demo.db.Database;
import com.owasp.demo.model.AuditLog;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AuditLogRepositoryTest {

    private static AuditLogRepository repo;

    @BeforeAll
    static void setup() throws SQLException {
        Database.init();
        repo = new AuditLogRepository();
    }

    @Test
    void log_persistsEvent() throws SQLException {
        repo.log("TEST_EVENT", "detail=test");
        List<AuditLog> logs = repo.findRecent(10);
        assertTrue(logs.stream().anyMatch(l -> "TEST_EVENT".equals(l.event())));
    }

    @Test
    void findRecent_respectsLimit() throws SQLException {
        for (int i = 0; i < 5; i++) {
            repo.log("LIMIT_TEST", "i=" + i);
        }
        List<AuditLog> logs = repo.findRecent(3);
        assertTrue(logs.size() <= 3);
    }

    @Test
    void findRecent_returnsNewestFirst() throws SQLException {
        repo.log("FIRST", "order=1");
        repo.log("SECOND", "order=2");
        List<AuditLog> logs = repo.findRecent(2);
        assertEquals("SECOND", logs.getFirst().event());
    }

    @Test
    void log_storesDetailsCorrectly() throws SQLException {
        repo.log("DETAIL_CHECK", "user=alice;ip=127.0.0.1");
        List<AuditLog> logs = repo.findRecent(1);
        assertEquals("user=alice;ip=127.0.0.1", logs.getFirst().details());
    }
}
