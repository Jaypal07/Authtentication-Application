package com.jaypal.authapp.auth.debug;

import com.jaypal.authapp.auth.infrastructure.cookie.CookieService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenDebugFilter extends OncePerRequestFilter {

    private final CookieService cookieService;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().contains("/auth/refresh");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain
    ) throws ServletException, IOException {

        logToken(request);
        chain.doFilter(request, response);
    }

    private void logToken(HttpServletRequest request) {

        String source = null;
        String token = null;

        String header = request.getHeader("X-Refresh-Token");
        if (header != null && !header.isBlank()) {
            source = "X-Refresh-Token";
            token = header.trim();
        }

        if (token == null) {
            String auth = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (auth != null && auth.toLowerCase().startsWith("bearer ")) {
                source = "Authorization";
                token = auth.substring(7).trim();
            }
        }

        if (token == null && request.getCookies() != null) {
            Optional<Cookie> cookie =
                    Arrays.stream(request.getCookies())
                            .filter(c ->
                                    cookieService
                                            .getRefreshTokenCookieName()
                                            .equals(c.getName())
                            )
                            .findFirst();

            if (cookie.isPresent()) {
                source = "Cookie";
                token = cookie.get().getValue();
            }
        }

        if (token == null) {
            log.warn("REFRESH DEBUG → no token found");
            return;
        }

        String hash = shortHash(token);

        log.info(
                "REFRESH DEBUG → source={}, hash={}",
                source,
                hash
        );

        decodePayload(token, hash);
    }

    private void decodePayload(String token, String hash) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                log.warn(
                        "REFRESH DEBUG → hash={} NOT JWT (parts={})",
                        hash,
                        parts.length
                );
                return;
            }

            String payload =
                    new String(
                            Base64.getUrlDecoder()
                                    .decode(parts[1]),
                            StandardCharsets.UTF_8
                    );

            log.info(
                    "REFRESH DEBUG → hash={} payload={}",
                    hash,
                    payload
            );

        } catch (Exception ex) {
            log.warn(
                    "REFRESH DEBUG → hash={} decode failed: {}",
                    hash,
                    ex.getMessage()
            );
        }
    }

    private String shortHash(String token) {
        try {
            MessageDigest digest =
                    MessageDigest.getInstance("SHA-256");
            byte[] hash =
                    digest.digest(
                            token.getBytes(StandardCharsets.UTF_8)
                    );
            return bytesToHex(hash).substring(0, 12);
        } catch (Exception e) {
            return "hash-error";
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
