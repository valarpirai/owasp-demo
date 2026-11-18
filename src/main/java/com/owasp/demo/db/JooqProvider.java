package com.owasp.demo.db;

import org.jooq.DSLContext;
import org.jooq.SQLDialect;
import org.jooq.impl.DSL;

import java.sql.SQLException;

public class JooqProvider {

    /**
     * Returns a jOOQ context on the pool. jOOQ borrows a connection for each
     * statement and gives it back when the statement ends, so callers never close anything.
     *
     * @return a context backed by the connection pool
     */
    public static DSLContext ctx() throws SQLException {
        return DSL.using(Database.dataSource(), SQLDialect.H2);
    }
}
