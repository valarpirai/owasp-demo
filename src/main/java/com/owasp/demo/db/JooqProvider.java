package com.owasp.demo.db;

import org.jooq.DSLContext;
import org.jooq.SQLDialect;
import org.jooq.impl.DSL;

import java.sql.Connection;
import java.sql.SQLException;

public class JooqProvider {

    public static DSLContext ctx() throws SQLException {
        Connection conn = Database.getConnection();
        return DSL.using(conn, SQLDialect.H2);
    }
}
