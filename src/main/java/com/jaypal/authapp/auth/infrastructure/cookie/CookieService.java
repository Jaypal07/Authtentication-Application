package com.jaypal.authapp.auth.infrastructure.cookie;

import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Service
@Getter
@Slf4j
public class CookieService {

    private final String refreshTokenCookieName;
    private final boolean cookieHttpOnly;
    private final boolean cookieSecure;
    private final String cookieDomain;
    private final String cookieSameSite;

    public CookieService(
            @Value("${security.jwt.refresh-token-cookie-name}") String refreshTokenCookieName,
            @Value("${security.jwt.cookie-http-only}") boolean cookieHttpOnly,
            @Value("${security.jwt.cookie-secure}") boolean cookieSecure,
            @Value("${security.jwt.cookie-domain}") String cookieDomain,
            @Value("${security.jwt.cookie-same-site}") String cookieSameSite
    ) {
        if ("None".equalsIgnoreCase(cookieSameSite) && !cookieSecure) {
            throw new IllegalStateException(
                    "SameSite=None requires Secure=true"
            );
        }

        this.refreshTokenCookieName = refreshTokenCookieName;
        this.cookieHttpOnly = cookieHttpOnly;
        this.cookieSecure = cookieSecure;
        this.cookieDomain = cookieDomain;
        this.cookieSameSite = cookieSameSite;
    }

    // ---------- SET / OVERWRITE ----------

    public void attachRefreshCookie(
            HttpServletResponse response,
            String jwt,
            int maxAgeSeconds
    ) {
        String encoded =
                URLEncoder.encode(jwt, StandardCharsets.UTF_8);

        ResponseCookie.ResponseCookieBuilder builder =
                ResponseCookie.from(refreshTokenCookieName, encoded)
                        .httpOnly(cookieHttpOnly)
                        .secure(cookieSecure)
                        .path("/")
                        .maxAge(maxAgeSeconds)
                        .sameSite(cookieSameSite);

        if (cookieDomain != null && !cookieDomain.isBlank()) {
            builder.domain(cookieDomain);
        }

        response.setHeader(
                HttpHeaders.SET_COOKIE,
                builder.build().toString()
        );
    }

    // ---------- CLEAR ----------

    public void clearRefreshCookie(HttpServletResponse response) {

        ResponseCookie.ResponseCookieBuilder builder =
                ResponseCookie.from(refreshTokenCookieName, "")
                        .httpOnly(cookieHttpOnly)
                        .secure(cookieSecure)
                        .path("/")
                        .maxAge(0)
                        .sameSite(cookieSameSite);

        if (cookieDomain != null && !cookieDomain.isBlank()) {
            builder.domain(cookieDomain);
        }

        response.setHeader(
                HttpHeaders.SET_COOKIE,
                builder.build().toString()
        );
    }

    public void addNoStoreHeader(HttpServletResponse response) {
        response.setHeader(
                HttpHeaders.CACHE_CONTROL,
                "no-store, no-cache, must-revalidate, max-age=0"
        );
        response.setHeader(HttpHeaders.PRAGMA, "no-cache");
    }
}
