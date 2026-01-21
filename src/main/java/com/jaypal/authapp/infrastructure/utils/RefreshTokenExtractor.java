package com.jaypal.authapp.infrastructure.utils;

import com.jaypal.authapp.exception.auth.InvalidRefreshTokenException;
import com.jaypal.authapp.exception.auth.MissingRefreshTokenException;
import com.jaypal.authapp.infrastructure.utils.extractor.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Refactored RefreshTokenExtractor following Strategy Pattern.
 * Extraction priority: Cookie → Header → Body
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RefreshTokenExtractor {

    private final CookieTokenExtractor cookieExtractor;
    private final HeaderTokenExtractor headerExtractor;
    private final BodyTokenExtractor bodyExtractor;
    private final TokenValidator tokenValidator;

    public Optional<String> extract(HttpServletRequest request) {
        log.debug("Starting refresh token extraction");

        return extractFromCookie(request)
                .or(() -> extractFromHeader(request))
                .or(() -> extractFromBody(request))
                .map(tokenValidator::validate);
    }

    private Optional<String> extractFromCookie(HttpServletRequest request) {
        return cookieExtractor.extract(request)
                .map(token -> {
                    log.debug("Refresh token found in cookie");
                    return token;
                });
    }

    private Optional<String> extractFromHeader(HttpServletRequest request) {
        return headerExtractor.extract(request)
                .map(token -> {
                    log.debug("Refresh token found in header");
                    return token;
                });
    }

    private Optional<String> extractFromBody(HttpServletRequest request) {
        return bodyExtractor.extract(request)
                .map(token -> {
                    log.debug("Refresh token found in request body");
                    return token;
                });
    }
}