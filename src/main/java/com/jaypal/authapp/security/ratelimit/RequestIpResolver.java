package com.jaypal.authapp.security.ratelimit;

import jakarta.servlet.http.HttpServletRequest;

public final class RequestIpResolver {

    private RequestIpResolver() {}

    public static String resolve(HttpServletRequest request) {
        if (request == null) {
            return "unknown";
        }

        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }

        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }

        return request.getRemoteAddr();
    }
}
