package com.owasp.demo.repository;

import com.owasp.demo.db.Database;

import java.sql.*;
import java.util.*;

public class DbBrowserRepository {

    public List<String> getTables() throws SQLException {
        List<String> tables = new ArrayList<>();
        try (Connection conn = Database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES " +
                "WHERE TABLE_SCHEMA = 'PUBLIC' ORDER BY TABLE_NAME")) {
            ResultSet rs = ps.executeQuery();
            while (rs.next()) tables.add(rs.getString(1));
        }
        return tables;
    }

    public List<String> getColumns(String table) throws SQLException {
        List<String> cols = new ArrayList<>();
        try (Connection conn = Database.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS " +
                "WHERE TABLE_SCHEMA = 'PUBLIC' AND TABLE_NAME = ? " +
                "ORDER BY ORDINAL_POSITION")) {
            ps.setString(1, table.toUpperCase());
            ResultSet rs = ps.executeQuery();
            while (rs.next()) cols.add(rs.getString(1));
        }
        return cols;
    }

    public int countRows(String table, String filter, List<String> columns) throws SQLException {
        String where = buildWhere(filter, columns);
        String sql = "SELECT COUNT(*) FROM \"" + table + "\"" + where;
        try (Connection conn = Database.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            bindFilter(ps, filter, columns, 1);
            ResultSet rs = ps.executeQuery();
            return rs.next() ? rs.getInt(1) : 0;
        }
    }

    public List<Map<String, Object>> fetchPage(
            String table, List<String> columns,
            String filter, String sortCol, String sortDir,
            int offset, int pageSize) throws SQLException {

        String safeSort = columns.contains(sortCol) ? "\"" + sortCol + "\"" : "\"" + columns.getFirst() + "\"";
        String safeDir = "DESC".equalsIgnoreCase(sortDir) ? "DESC" : "ASC";
        String where = buildWhere(filter, columns);
        String sql = "SELECT * FROM \"" + table + "\"" + where +
                     " ORDER BY " + safeSort + " " + safeDir +
                     " LIMIT ? OFFSET ?";

        List<Map<String, Object>> rows = new ArrayList<>();
        try (Connection conn = Database.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            int idx = bindFilter(ps, filter, columns, 1);
            ps.setInt(idx++, pageSize);
            ps.setInt(idx, offset);
            ResultSet rs = ps.executeQuery();
            ResultSetMetaData meta = rs.getMetaData();
            int colCount = meta.getColumnCount();
            while (rs.next()) {
                Map<String, Object> row = new LinkedHashMap<>();
                for (int i = 1; i <= colCount; i++) {
                    row.put(meta.getColumnName(i), rs.getObject(i));
                }
                rows.add(row);
            }
        }
        return rows;
    }

    private String buildWhere(String filter, List<String> columns) {
        if (filter == null || filter.isBlank()) return "";
        StringJoiner sj = new StringJoiner(" OR ");
        for (String col : columns) sj.add("CAST(\"" + col + "\" AS VARCHAR) LIKE ?");
        return " WHERE " + sj;
    }

    private int bindFilter(PreparedStatement ps, String filter, List<String> columns, int startIdx) throws SQLException {
        if (filter == null || filter.isBlank()) return startIdx;
        String pattern = "%" + filter + "%";
        for (int i = 0; i < columns.size(); i++) {
            ps.setString(startIdx + i, pattern);
        }
        return startIdx + columns.size();
    }
}
