package com.jaypal.authapp.infrastructure.audit.context;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Dedicated component for User-Agent extraction.
 * Follows Single Responsibility Principle.
 */
public final class UserAgentExtractor {

    private static final String USER_AGENT = "User-Agent";
    private static final String UNKNOWN = "unknown";
    private static final int MAX_LENGTH = 512;

    private UserAgentExtractor() {
        throw new UnsupportedOperationException("Utility class");
    }

    public static String extract(HttpServletRequest request) {
        if (request == null) {
            return UNKNOWN;
        }

        String userAgent = request.getHeader(USER_AGENT);

        if (userAgent == null || userAgent.isBlank()) {
            return UNKNOWN;
        }

        return truncate(userAgent);
    }

    private static String truncate(String userAgent) {
        return userAgent.length() > MAX_LENGTH
                ? userAgent.substring(0, MAX_LENGTH)
                : userAgent;
    }
}
