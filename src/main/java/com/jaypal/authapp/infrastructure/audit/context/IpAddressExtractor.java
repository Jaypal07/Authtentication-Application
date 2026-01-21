package com.jaypal.authapp.infrastructure.audit.context;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

/**
 * Dedicated component for IP address extraction.
 * Follows Single Responsibility Principle.
 */
@Slf4j
public final class IpAddressExtractor {

    private static final String X_FORWARDED_FOR = "X-Forwarded-For";
    private static final String X_REAL_IP = "X-Real-IP";
    private static final String UNKNOWN = "unknown";

    // Configurable trusted headers for proxy scenarios
    private static final List<String> TRUSTED_HEADERS = List.of(
            X_FORWARDED_FOR,
            X_REAL_IP
    );

    private IpAddressExtractor() {
        throw new UnsupportedOperationException("Utility class");
    }

    /**
     * Extracts IP address from request.
     * In production, trust only the container's remote address.
     * Proxy headers can be spoofed and should only be used if behind a trusted reverse proxy.
     */
    public static String extract(HttpServletRequest request) {
        if (request == null) {
            return UNKNOWN;
        }

        // Primary: Always trust the container
        String ip = request.getRemoteAddr();

        if (isValidIp(ip)) {
            return ip;
        }

        log.warn("Invalid or missing remote address, falling back to UNKNOWN");
        return UNKNOWN;
    }

    /**
     * Extracts IP from proxy headers (use only if behind trusted reverse proxy).
     * This method should be used cautiously as headers can be spoofed.
     */
    public static String extractFromProxyHeaders(HttpServletRequest request) {
        if (request == null) {
            return UNKNOWN;
        }

        // Check X-Forwarded-For (leftmost is original client)
        String xForwardedFor = request.getHeader(X_FORWARDED_FOR);
        if (xForwardedFor != null && !xForwardedFor.isBlank() && !UNKNOWN.equalsIgnoreCase(xForwardedFor)) {
            String ip = extractFirstIp(xForwardedFor);
            if (isValidIp(ip)) {
                return ip;
            }
        }

        // Check X-Real-IP
        String xRealIp = request.getHeader(X_REAL_IP);
        if (isValidIp(xRealIp) && !UNKNOWN.equalsIgnoreCase(xRealIp)) {
            return xRealIp.trim();
        }

        // Fallback to remote address
        return extract(request);
    }

    private static String extractFirstIp(String xForwardedFor) {
        int commaIndex = xForwardedFor.indexOf(',');
        return commaIndex > 0
                ? xForwardedFor.substring(0, commaIndex).trim()
                : xForwardedFor.trim();
    }

    private static boolean isValidIp(String ip) {
        return ip != null && !ip.isBlank() && !UNKNOWN.equalsIgnoreCase(ip);
    }
}
