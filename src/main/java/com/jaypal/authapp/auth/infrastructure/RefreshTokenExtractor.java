package com.jaypal.authapp.auth.infrastructure;

import com.jaypal.authapp.auth.exception.MissingRefreshTokenException;
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
    private static final int MAX_TOKEN_LENGTH = 2048;

    private final CookieService cookieService;

    public Optional<String> extract(HttpServletRequest request) {
        return extractFromCookie(request)
                .or(() -> extractFromHeader(request))
                .map(this::validate);
    }

    private Optional<String> extractFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return Optional.empty();

        return Arrays.stream(cookies)
                .filter(Objects::nonNull)
                .filter(c -> cookieService.getRefreshTokenCookieName().equals(c.getName()))
                .map(Cookie::getValue)
                .filter(v -> v != null && !v.isBlank())
                .findFirst();
    }

    private Optional<String> extractFromHeader(HttpServletRequest request) {
        String value = request.getHeader(REFRESH_HEADER);
        return value == null || value.isBlank()
                ? Optional.empty()
                : Optional.of(value.trim());
    }

    private String validate(String token) {
        if (token.length() > MAX_TOKEN_LENGTH) {
            throw new MissingRefreshTokenException();
        }

        if (!token.matches("^[A-Za-z0-9._~-]+$")) {
            throw new MissingRefreshTokenException();
        }

        return token;
    }
}
