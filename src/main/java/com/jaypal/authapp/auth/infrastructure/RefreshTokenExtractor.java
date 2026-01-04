package com.jaypal.authapp.auth.infrastructure;

import com.jaypal.authapp.auth.infrastructure.cookie.CookieService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class RefreshTokenExtractor {

    private final CookieService cookieService;

    public Optional<String> extract(HttpServletRequest request) {

        // 1️⃣ Explicit refresh header wins
        String headerToken = request.getHeader("X-Refresh-Token");
        if (headerToken != null && !headerToken.isBlank()) {
            return Optional.of(headerToken.trim());
        }

        // 2️⃣ Authorization bearer fallback
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null &&
                authHeader.toLowerCase().startsWith("bearer ")) {
            return Optional.of(authHeader.substring(7).trim());
        }

        // 3️⃣ Cookie last
        if (request.getCookies() != null) {
            return Arrays.stream(request.getCookies())
                    .filter(c ->
                            cookieService
                                    .getRefreshTokenCookieName()
                                    .equals(c.getName())
                    )
                    .map(Cookie::getValue)
                    .map(v ->
                            URLDecoder.decode(
                                    v,
                                    StandardCharsets.UTF_8
                            )
                    )
                    .filter(v -> !v.isBlank())
                    .findFirst();
        }

        return Optional.empty();
    }
}
