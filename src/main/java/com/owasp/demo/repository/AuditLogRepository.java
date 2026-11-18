package com.owasp.demo.repository;

import com.owasp.demo.db.JooqProvider;
import com.owasp.demo.model.AuditLog;
import org.jooq.DSLContext;
import org.jooq.Record;
import org.jooq.Result;

import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;

import static org.jooq.impl.DSL.field;
import static org.jooq.impl.DSL.table;


public class AuditLogRepository {

    public void log(String event, String details) throws SQLException {
        DSLContext ctx = JooqProvider.ctx();
        ctx.insertInto(table("audit_log"))
            .set(field("event"), event)
            .set(field("details"), details)
            .execute();
    }

    public List<AuditLog> findRecent(int limit) throws SQLException {
        DSLContext ctx = JooqProvider.ctx();
        Result<Record> result = ctx.select()
            .from(table("audit_log"))
            .orderBy(field("id").desc())
            .limit(limit)
            .fetch();

        return result.map(r -> new AuditLog(
            r.get(0, Integer.class),
            r.get(1, Timestamp.class).toLocalDateTime(),
            r.get(2, String.class),
            r.get(3, String.class)
        ));
    }
}
