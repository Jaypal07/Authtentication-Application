package com.jaypal.authapp.service.auth.web;

import com.jaypal.authapp.dto.auth.AuthLoginResult;
import com.jaypal.authapp.infrastructure.utils.CookieService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Slf4j
@Component
@RequiredArgsConstructor
public class RefreshCookieAttacher {

    private final CookieService cookieService;

    public void attach(HttpServletResponse response, AuthLoginResult result) {
        long ttlSeconds = calculateTtl(result);

        log.debug(
                "Preparing refresh cookie | userId={} ttlSeconds={}",
                result.user().id(),
                ttlSeconds
        );

        validateTtl(ttlSeconds, result);

        cookieService.attachRefreshCookie(
                response,
                result.refreshToken(),
                (int) ttlSeconds
        );

        log.debug(
                "Refresh cookie attached | userId={} ttlSeconds={}",
                result.user().id(),
                ttlSeconds
        );
    }

    private long calculateTtl(AuthLoginResult result) {
        long now = Instant.now().getEpochSecond();
        long expiresAt = result.refreshExpiresAtEpochSeconds();
        return expiresAt - now;
    }

    private void validateTtl(long ttlSeconds, AuthLoginResult result) {
        if (ttlSeconds <= 0) {
            log.error(
                    "Invalid refresh TTL detected | userId={} expiresAt={} now={}",
                    result.user().id(),
                    result.refreshExpiresAtEpochSeconds(),
                    Instant.now().getEpochSecond()
            );
            throw new IllegalStateException("Invalid refresh token TTL");
        }
    }
}
