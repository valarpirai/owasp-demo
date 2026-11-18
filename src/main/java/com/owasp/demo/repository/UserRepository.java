package com.owasp.demo.repository;

import com.owasp.demo.db.JooqProvider;
import com.owasp.demo.model.User;
import com.owasp.demo.util.PasswordHasher;
import org.jooq.DSLContext;
import org.jooq.Record;
import org.jooq.Result;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

import static org.jooq.impl.DSL.field;
import static org.jooq.impl.DSL.table;

public class UserRepository {

    public Optional<User> findByUsernameAndPasswordSafe(String username, String password) throws SQLException {
        List<User> found = findByUsernameSafe(username);
        if (found.isEmpty()) {
            PasswordHasher.verifyAgainstDummy(password);
            return Optional.empty();
        }
        User user = found.getFirst();
        return PasswordHasher.verify(password, user.password()) ? Optional.of(user) : Optional.empty();
    }

    public List<User> findAllUnsafe(String usernameInput) throws SQLException {
        DSLContext ctx = JooqProvider.ctx();
        String sql = "SELECT id, username, password, role FROM users WHERE username = '" + usernameInput + "'";
        return ctx.fetch(sql).map(this::map);
    }

    public List<User> findByUsernameSafe(String username) throws SQLException {
        DSLContext ctx = JooqProvider.ctx();
        return ctx.select()
            .from(table("users"))
            .where(field("username").eq(username))
            .fetch()
            .map(this::map);
    }

    public List<User> findAll() throws SQLException {
        DSLContext ctx = JooqProvider.ctx();
        return ctx.select()
            .from(table("users"))
            .fetch()
            .map(this::map);
    }

    private User map(Record r) {
        return new User(
            r.get(0, Integer.class),
            r.get(1, String.class),
            r.get(2, String.class),
            r.get(3, String.class)
        );
    }
}
