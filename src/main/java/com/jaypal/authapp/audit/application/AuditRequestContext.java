package com.jaypal.authapp.audit.application;

public record AuditRequestContext(
        String ipAddress,
        String userAgent,
        String userId // nullable
) {}
