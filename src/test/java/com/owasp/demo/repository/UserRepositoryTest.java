package com.owasp.demo.repository;

import com.owasp.demo.db.Database;
import com.owasp.demo.model.User;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class UserRepositoryTest {

    private static UserRepository repo;

    @BeforeAll
    static void setup() throws SQLException {
        Database.init();
        repo = new UserRepository();
    }

    @Test
    void findByUsernameAndPasswordSafe_returnsUserOnCorrectCredentials() throws SQLException {
        Optional<User> user = repo.findByUsernameAndPasswordSafe("admin", "admin123");
        assertTrue(user.isPresent());
        assertEquals("admin", user.get().username());
        assertEquals("ADMIN", user.get().role());
    }

    @Test
    void findByUsernameAndPasswordSafe_returnsEmptyOnWrongPassword() throws SQLException {
        Optional<User> user = repo.findByUsernameAndPasswordSafe("admin", "wrong");
        assertTrue(user.isEmpty());
    }

    @Test
    void findByUsernameAndPasswordSafe_resistsSqlInjection() throws SQLException {
        // Classic injection attempt — should return empty, not bypass auth
        Optional<User> user = repo.findByUsernameAndPasswordSafe("' OR '1'='1", "anything");
        assertTrue(user.isEmpty());
    }

    @Test
    void findAll_returnsBothSeedUsers() throws SQLException {
        List<User> users = repo.findAll();
        assertTrue(users.size() >= 2);
        assertTrue(users.stream().anyMatch(u -> u.username().equals("admin")));
        assertTrue(users.stream().anyMatch(u -> u.username().equals("user")));
    }

    @Test
    void findByUsernameSafe_returnsMatchingUser() throws SQLException {
        List<User> users = repo.findByUsernameSafe("user");
        assertEquals(1, users.size());
        assertEquals("user", users.getFirst().username());
        assertEquals("USER", users.getFirst().role());
    }

    @Test
    void findByUsernameSafe_returnsEmptyForUnknownUser() throws SQLException {
        List<User> users = repo.findByUsernameSafe("nonexistent");
        assertTrue(users.isEmpty());
    }

    @Test
    void findAllUnsafe_isVulnerableToInjection() throws SQLException {
        // The OR injection should return all rows — demonstrating the vulnerability
        List<User> users = repo.findAllUnsafe("' OR '1'='1");
        assertTrue(users.size() >= 2, "SQL injection should return all users");
    }

    @Test
    void findAllUnsafe_returnsCorrectUserForNormalInput() throws SQLException {
        List<User> users = repo.findAllUnsafe("admin");
        assertEquals(1, users.size());
        assertEquals("admin", users.getFirst().username());
    }
}
