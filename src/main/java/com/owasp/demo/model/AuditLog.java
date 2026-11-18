package com.owasp.demo.model;

import java.time.LocalDateTime;

public record AuditLog(int id, LocalDateTime eventTime, String event, String details) {}
