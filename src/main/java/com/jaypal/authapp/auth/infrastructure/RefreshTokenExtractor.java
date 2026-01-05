package com.jaypal.authapp.auth.infrastructure;

import com.jaypal.authapp.auth.infrastructure.cookie.CookieService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class RefreshTokenExtractor {

    private final CookieService cookieService;

    public Optional<String> extract(HttpServletRequest request) {

        // 1️⃣ Cookie is the primary source (browser-safe, CSRF-aware)
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            Optional<String> fromCookie =
                    Arrays.stream(cookies)
                            .filter(c ->
                                    cookieService
                                            .getRefreshTokenCookieName()
                                            .equals(c.getName())
                            )
                            .map(Cookie::getValue)
                            .filter(v -> v != null && !v.isBlank())
                            .findFirst();

            if (fromCookie.isPresent()) {
                return fromCookie;
            }
        }

        // 2️⃣ Explicit refresh token header (non-browser clients)
        String refreshHeader = request.getHeader("X-Refresh-Token");
        if (refreshHeader != null && !refreshHeader.isBlank()) {
            return Optional.of(refreshHeader.trim());
        }

        // 3️⃣ Authorization header LAST and OPTIONAL
        // Only for controlled internal clients
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return Optional.of(authHeader.substring(7).trim());
        }

        return Optional.empty();
    }
}
