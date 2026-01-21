package com.jaypal.authapp.infrastructure.audit.resolver;

import com.jaypal.authapp.dto.auth.AuthLoginResult;
import com.jaypal.authapp.dto.auth.TokenResponse;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

/**
 * Refactored IdentityResolver with improved null safety and readability.
 * Uses Optional for cleaner null handling.
 */
@Slf4j
@Component
public class IdentityResolver {

    private static final String ANONYMOUS_USER = "anonymousUser";

    public UUID fromSecurityContext() {
        return extractFromAuthentication()
                .orElse(null);
    }

    public UUID fromResult(Object result) {
        return extractFromResult(result)
                .orElse(null);
    }

    private Optional<UUID> extractFromAuthentication() {
        try {
            return Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication())
                    .filter(Authentication::isAuthenticated)
                    .map(Authentication::getPrincipal)
                    .filter(principal -> !ANONYMOUS_USER.equals(principal))
                    .filter(AuthPrincipal.class::isInstance)
                    .map(AuthPrincipal.class::cast)
                    .map(AuthPrincipal::getUserId);

        } catch (Exception ex) {
            log.debug("Failed to extract user ID from security context", ex);
            return Optional.empty();
        }
    }

    private Optional<UUID> extractFromResult(Object result) {
        try {
            if (result instanceof ResponseEntity<?> responseEntity) {
                return extractFromResponseEntity(responseEntity);
            }

            if (result instanceof AuthLoginResult authLoginResult) {
                return Optional.ofNullable(authLoginResult.user())
                        .map(user -> user.id());
            }

            return Optional.empty();

        } catch (Exception ex) {
            log.debug("Failed to extract user ID from result", ex);
            return Optional.empty();
        }
    }

    private Optional<UUID> extractFromResponseEntity(ResponseEntity<?> responseEntity) {
        return Optional.ofNullable(responseEntity.getBody())
                .filter(TokenResponse.class::isInstance)
                .map(TokenResponse.class::cast)
                .map(TokenResponse::user)
                .map(user -> user.id());
    }
}
