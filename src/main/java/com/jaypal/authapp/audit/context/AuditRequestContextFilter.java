package com.jaypal.authapp.audit.context;

import com.jaypal.authapp.audit.application.AuditRequestContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@Order(1)
public class AuditRequestContextFilter extends OncePerRequestFilter {

    private static final String X_FORWARDED_FOR = "X-Forwarded-For";
    private static final String X_REAL_IP = "X-Real-IP";
    private static final String USER_AGENT = "User-Agent";
    private static final String UNKNOWN = "unknown";

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain chain
    ) throws ServletException, IOException {

        try {
            final String ipAddress = extractIpAddress(request);
            final String userAgent = extractUserAgent(request);

            final AuditRequestContext context = new AuditRequestContext(ipAddress, userAgent);
            AuditContextHolder.setContext(context);

            log.trace("Audit context initialized: ip={}, ua={}",
                    maskIp(ipAddress), maskUserAgent(userAgent));

            chain.doFilter(request, response);

        } finally {
            AuditContextHolder.clear();
        }
    }

    private String extractIpAddress(HttpServletRequest request) {
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

    private String extractUserAgent(HttpServletRequest request) {
        final String userAgent = request.getHeader(USER_AGENT);

        if (userAgent == null || userAgent.isBlank()) {
            return UNKNOWN;
        }

        return userAgent.length() > 512 ? userAgent.substring(0, 512) : userAgent;
    }

    private String maskIp(String ip) {
        if (ip == null || ip.equals(UNKNOWN)) {
            return UNKNOWN;
        }

        final int lastDot = ip.lastIndexOf('.');
        return lastDot > 0 ? ip.substring(0, lastDot) + ".***" : "***";
    }

    private String maskUserAgent(String ua) {
        if (ua == null || ua.length() <= 20) {
            return "***";
        }
        return ua.substring(0, 20) + "...";
    }
}

/*
CHANGELOG:
1. Created filter to capture request context BEFORE async execution
2. Extracts IP from X-Forwarded-For, X-Real-IP, or RemoteAddr
3. Handles proxy chains (takes first IP from X-Forwarded-For)
4. Truncates User-Agent to 512 chars to prevent overflow
5. Stores context in ThreadLocal via AuditContextHolder
6. Clears context in finally block to prevent leaks
7. Added PII masking for logs
8. Set as @Order(1) to run before security filters
*/