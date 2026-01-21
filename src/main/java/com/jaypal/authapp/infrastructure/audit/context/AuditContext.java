package com.jaypal.authapp.infrastructure.audit.context;

import com.jaypal.authapp.dto.audit.AuditRequestContext;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Refactored AuditContext following Single Responsibility Principle.
 * Delegates extraction logic to specialized components.
 */
public final class AuditContext {

    private AuditContext() {
        throw new UnsupportedOperationException("Utility class");
    }

    public static AuditRequestContext fromRequest(HttpServletRequest request) {
        if (request == null) {
            return null;
        }

        String ipAddress = IpAddressExtractor.extract(request);
        String userAgent = UserAgentExtractor.extract(request);

        return new AuditRequestContext(ipAddress, userAgent, null);
    }

    public static AuditRequestContext fromThreadLocal() {
        return AuditContextHolder.getContext();
    }
}