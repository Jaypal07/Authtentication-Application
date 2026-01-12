package com.jaypal.authapp.audit.context;

import com.jaypal.authapp.audit.application.AuditRequestContext;
import jakarta.servlet.http.HttpServletRequest;

public final class AuditContext {

    private static final String X_FORWARDED_FOR = "X-Forwarded-For";
    private static final String X_REAL_IP = "X-Real-IP";
    private static final String USER_AGENT = "User-Agent";
    private static final String UNKNOWN = "unknown";

    private AuditContext() {
        throw new UnsupportedOperationException("Utility class");
    }

    public static AuditRequestContext fromRequest(HttpServletRequest request) {
        if (request == null) {
            return null;
        }

        final String ipAddress = extractIpAddress(request);
        final String userAgent = extractUserAgent(request);

        return new AuditRequestContext(ipAddress, userAgent);
    }

    public static AuditRequestContext fromThreadLocal() {
        return AuditContextHolder.getContext();
    }

    private static String extractIpAddress(HttpServletRequest request) {
        String ip = request.getHeader(X_FORWARDED_FOR);

        if (ip != null && !ip.isBlank() && !UNKNOWN.equalsIgnoreCase(ip)) {
            final int commaIndex = ip.indexOf(',');
            return commaIndex > 0 ? ip.substring(0, commaIndex).trim() : ip.trim();
        }

        ip = request.getHeader(X_REAL_IP);
        if (ip != null && !ip.isBlank() && !UNKNOWN.equalsIgnoreCase(ip)) {
            return ip.trim();
        }

        ip = request.getRemoteAddr();
        return ip != null ? ip : UNKNOWN;
    }

    private static String extractUserAgent(HttpServletRequest request) {
        final String userAgent = request.getHeader(USER_AGENT);

        if (userAgent == null || userAgent.isBlank()) {
            return UNKNOWN;
        }

        return userAgent.length() > 512 ? userAgent.substring(0, 512) : userAgent;
    }
}

/*
CHANGELOG:
1. Added fromRequest() for manual context creation
2. Added fromThreadLocal() as convenience method
3. Made class non-instantiable with throwing constructor
4. Kept utility methods for extracting IP and User-Agent
5. This can now be used if you need to manually create audit context
*/