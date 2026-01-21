package com.jaypal.authapp.service.auth.web;

import com.jaypal.authapp.config.properties.RateLimitProperties;
import com.jaypal.authapp.domain.token.exception.RefreshTokenExpiredException;
import com.jaypal.authapp.domain.token.exception.RefreshTokenNotFoundException;
import com.jaypal.authapp.domain.token.exception.RefreshTokenRevokedException;
import com.jaypal.authapp.dto.auth.AuthLoginResult;
import com.jaypal.authapp.dto.auth.RefreshTokenRequest;
import com.jaypal.authapp.exception.auth.MissingRefreshTokenException;
import com.jaypal.authapp.infrastructure.ratelimit.*;
import com.jaypal.authapp.infrastructure.utils.RefreshTokenExtractor;
import com.jaypal.authapp.service.auth.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class RefreshWebOperation {

    private final RefreshTokenExtractor refreshTokenExtractor;
    private final RefreshCookieAttacher cookieAttacher;
    private final InvalidRefreshRateLimiter rateLimiter;

    public AuthLoginResult execute(
            HttpServletRequest request,
            HttpServletResponse response,
            RefreshTokenRequest body,
            AuthService authService
    ) {
        String ip = RequestIpResolver.resolve(request);
        log.debug("Refresh flow started | ip={}", ip);

        try {
            String refreshToken = extractToken(request, body, ip);
            AuthLoginResult result = authService.refresh(refreshToken);

            log.debug(
                    "Refresh successful | userId={} newRefreshExpiresAt={}",
                    result.user().id(),
                    result.refreshExpiresAtEpochSeconds()
            );

            cookieAttacher.attach(response, result);

            log.debug("Refresh flow completed | userId={}", result.user().id());
            return result;

        } catch (RefreshTokenNotFoundException |
                 RefreshTokenExpiredException |
                 RefreshTokenRevokedException |
                 MissingRefreshTokenException ex) {

            rateLimiter.checkAndEnforce(ip, ex);
            throw ex;
        }
    }

    private String extractToken(
            HttpServletRequest request,
            RefreshTokenRequest body,
            String ip
    ) {
        return refreshTokenExtractor.extract(request)
                .or(() -> extractFromBody(body))
                .orElseThrow(() -> {
                    log.warn("Refresh failed. No refresh token present | ip={}", ip);
                    return new MissingRefreshTokenException();
                });
    }

    private Optional<String> extractFromBody(RefreshTokenRequest body) {
        return Optional.ofNullable(body)
                .map(RefreshTokenRequest::refreshToken)
                .filter(t -> !t.isBlank())
                .map(token -> {
                    log.debug(
                            "Refresh token extracted from body | length={} prefix={}",
                            token.length(),
                            token.substring(0, Math.min(8, token.length()))
                    );
                    return token;
                });
    }
}