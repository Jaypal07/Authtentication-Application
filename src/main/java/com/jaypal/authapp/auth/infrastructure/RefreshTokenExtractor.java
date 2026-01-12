package com.jaypal.authapp.auth.infrastructure;

import com.jaypal.authapp.auth.infrastructure.cookie.CookieService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class RefreshTokenExtractor {

    private static final String REFRESH_HEADER = "X-Refresh-Token";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final int MAX_TOKEN_LENGTH = 2048;

    private final CookieService cookieService;

    public Optional<String> extract(HttpServletRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("HttpServletRequest must not be null");
        }

        Optional<String> token = extractFromCookie(request);
        if (token.isPresent()) {
            log.debug("Refresh token extracted from cookie");
            return validate(token.get());
        }

        token = extractFromCustomHeader(request);
        if (token.isPresent()) {
            log.debug("Refresh token extracted from custom header");
            return validate(token.get());
        }

        log.debug("No refresh token found in request");
        return Optional.empty();
    }

    private Optional<String> extractFromCookie(HttpServletRequest request) {
        final Cookie[] cookies = request.getCookies();

        if (cookies == null || cookies.length == 0) {
            return Optional.empty();
        }

        return Arrays.stream(cookies)
                .filter(cookie -> cookie != null &&
                        cookieService.getRefreshTokenCookieName().equals(cookie.getName()))
                .map(Cookie::getValue)
                .filter(value -> value != null && !value.isBlank())
                .findFirst();
    }

    private Optional<String> extractFromCustomHeader(HttpServletRequest request) {
        final String headerValue = request.getHeader(REFRESH_HEADER);

        if (headerValue == null || headerValue.isBlank()) {
            return Optional.empty();
        }

        return Optional.of(headerValue.trim());
    }

    private Optional<String> validate(String token) {
        if (token == null || token.isBlank()) {
            log.warn("Refresh token validation failed: null or blank");
            return Optional.empty();
        }

        if (token.length() > MAX_TOKEN_LENGTH) {
            log.warn("Refresh token validation failed: exceeds max length ({} > {})",
                    token.length(), MAX_TOKEN_LENGTH);
            return Optional.empty();
        }

        if (token.contains("\n") || token.contains("\r")) {
            log.warn("Refresh token validation failed: contains line breaks");
            return Optional.empty();
        }

        return Optional.of(token);
    }
}

/*
CHANGELOG:
1. Removed Authorization header as refresh token source (security risk)
2. Added null check for HttpServletRequest parameter
3. Added token validation method (max length, no line breaks)
4. Extracted constants for header names and max length
5. Added comprehensive logging for debugging
6. Simplified extraction logic by removing Bearer token support
7. Added null checks in cookie stream filter
8. Made cookie extraction more defensive against null cookies
9. Added explicit trim() for custom header values
10. Separated extraction sources into dedicated methods for clarity
11. Cookie remains primary source, custom header is fallback
*/