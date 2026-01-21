package com.jaypal.authapp.infrastructure.utils.extractor;

import com.jaypal.authapp.infrastructure.utils.CookieService;
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
public class CookieTokenExtractor {

    private final CookieService cookieService;

    public Optional<String> extract(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (cookies == null) {
            log.debug("No cookies present in request");
            return Optional.empty();
        }

        return Arrays.stream(cookies)
                .filter(Objects::nonNull)
                .filter(c -> cookieService.getRefreshTokenCookieName().equals(c.getName()))
                .map(Cookie::getValue)
                .filter(this::isValid)
                .findFirst();
    }

    private boolean isValid(String value) {
        boolean valid = value != null && !value.isBlank();
        if (!valid) {
            log.debug("Refresh token cookie present but empty");
        }
        return valid;
    }
}
