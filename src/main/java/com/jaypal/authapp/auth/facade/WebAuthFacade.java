package com.jaypal.authapp.auth.facade;

import com.jaypal.authapp.auth.application.AuthService;
import com.jaypal.authapp.auth.dto.AuthLoginResult;
import com.jaypal.authapp.auth.dto.RefreshTokenRequest;
import com.jaypal.authapp.auth.exception.MissingRefreshTokenException;
import com.jaypal.authapp.auth.infrastructure.RefreshTokenExtractor;
import com.jaypal.authapp.auth.infrastructure.cookie.CookieService;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import com.jaypal.authapp.security.ratelimit.InvalidRefreshTokenRateLimiter;
import com.jaypal.authapp.security.ratelimit.RequestIpResolver;
import com.jaypal.authapp.token.exception.RefreshTokenExpiredException;
import com.jaypal.authapp.token.exception.RefreshTokenNotFoundException;
import com.jaypal.authapp.token.exception.RefreshTokenRevokedException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class WebAuthFacade {

    private final AuthService authService;
    private final CookieService cookieService;
    private final RefreshTokenExtractor refreshTokenExtractor;
    private final InvalidRefreshTokenRateLimiter invalidRefreshLimiter;

    /* =========================
       LOGIN FLOW
       ========================= */

    public AuthLoginResult login(AuthPrincipal principal, HttpServletResponse response) {
        if (principal == null) {
            throw new IllegalArgumentException("AuthPrincipal must not be null");
        }

        log.debug(
                "Login flow started | userId={}",
                principal.getUserId()
        );

        AuthLoginResult result = authService.login(principal);

        log.debug(
                "Login tokens issued | userId={} refreshExpiresAt={}",
                result.user().getId(),
                result.refreshExpiresAtEpochSeconds()
        );

        attachRefreshCookie(response, result);

        log.debug(
                "Login flow completed | userId={}",
                principal.getUserId()
        );

        return result;
    }

    /* =========================
       REFRESH FLOW
       ========================= */

    public AuthLoginResult refresh(
            HttpServletRequest request,
            HttpServletResponse response,
            RefreshTokenRequest body
    ) {
        log.debug("Refresh flow started");

        String ip = RequestIpResolver.resolve(request);

        try {
            String refreshToken =
                    refreshTokenExtractor.extract(request)
                            .or(() -> Optional.ofNullable(body)
                                    .map(RefreshTokenRequest::refreshToken)
                                    .filter(t -> !t.isBlank())
                                    .map(token -> {
                                        log.debug(
                                                "Refresh token extracted from body | length={} prefix={}",
                                                token.length(),
                                                token.substring(0, Math.min(8, token.length()))
                                        );
                                        return token;
                                    }))
                            .orElseThrow(() -> {
                                log.warn("Refresh failed: no refresh token present");
                                return new MissingRefreshTokenException();
                            });

            AuthLoginResult result = authService.refresh(refreshToken);

            log.debug(
                    "Refresh successful | userId={} newRefreshExpiresAt={}",
                    result.user().getId(),
                    result.refreshExpiresAtEpochSeconds()
            );

            attachRefreshCookie(response, result);

            log.debug("Refresh flow completed | userId={}", result.user().getId());

            return result;

        } catch (RefreshTokenNotFoundException |
                 RefreshTokenExpiredException |
                 RefreshTokenRevokedException |
                 MissingRefreshTokenException ex) {

            // 🔥 INVALID REFRESH → RATE LIMIT HERE
            invalidRefreshLimiter.check(ip);

            log.warn(
                    "Invalid refresh attempt | ip={} reason={}",
                    ip,
                    ex.getClass().getSimpleName()
            );

            throw ex;
        }
    }



    /* =========================
       LOGOUT FLOW
       ========================= */

    public void logout(HttpServletRequest request, HttpServletResponse response) {
        log.debug("Logout flow started");

        refreshTokenExtractor.extract(request).ifPresentOrElse(
                token -> {
                    log.debug(
                            "Logout refresh token found | length={} prefix={}",
                            token.length(),
                            token.substring(0, Math.min(8, token.length()))
                    );
                    authService.logout(token);
                },
                () -> log.debug("Logout called without refresh token")
        );

        cookieService.clearRefreshCookie(response);
        cookieService.addNoStoreHeader(response);

        log.debug("Logout flow completed");
    }

    /* =========================
       INTERNAL HELPERS
       ========================= */

    private void attachRefreshCookie(HttpServletResponse response, AuthLoginResult result) {
        long now = Instant.now().getEpochSecond();
        long expiresAt = result.refreshExpiresAtEpochSeconds();
        long ttlSeconds = expiresAt - now;
        log.debug(
                "Attaching refresh cookie | userId={} now={} expiresAt={} ttlSeconds={}",
                result.user().getId(),
                now,
                expiresAt,
                ttlSeconds
        );

        if (ttlSeconds <= 0) {
            log.error(
                    "Invalid refresh TTL detected | userId={} ttlSeconds={}",
                    result.user().getId(),
                    ttlSeconds
            );
            throw new IllegalStateException("Invalid refresh token TTL");
        }

        cookieService.attachRefreshCookie(
                response,
                result.refreshToken(),
                (int) ttlSeconds
        );

        log.debug(
                "Refresh cookie attached | userId={} ttlSeconds={}",
                result.user().getId(),
                ttlSeconds
        );
    }
}
