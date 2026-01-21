package com.jaypal.authapp.infrastructure.audit.resolver;

import com.jaypal.authapp.domain.audit.entity.AuthFailureReason;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Refactored FailureReasonResolver following SOLID principles:
 * - Single Responsibility: Orchestrates exception mapping
 * - Open/Closed: Extensible via strategy pattern
 * - Liskov Substitution: All strategies are interchangeable
 * - Dependency Inversion: Depends on ExceptionMappingStrategy abstraction
 */
@Slf4j
@Component
public class FailureReasonResolver {

    private final List<ExceptionMappingStrategy> mappingStrategies;
    private final ExceptionUnwrapper exceptionUnwrapper;

    public FailureReasonResolver(
            List<ExceptionMappingStrategy> mappingStrategies,
            ExceptionUnwrapper exceptionUnwrapper
    ) {
        this.mappingStrategies = Objects.requireNonNull(mappingStrategies, "mappingStrategies must not be null");
        this.exceptionUnwrapper = Objects.requireNonNull(exceptionUnwrapper, "exceptionUnwrapper must not be null");
    }

    public AuthFailureReason resolve(Throwable ex) {
        Objects.requireNonNull(ex, "Exception cannot be null");

        Throwable rootCause = exceptionUnwrapper.unwrap(ex);

        return mappingStrategies.stream()
                .filter(strategy -> strategy.supports(rootCause))
                .findFirst()
                .map(strategy -> strategy.mapToFailureReason(rootCause))
                .orElseGet(() -> handleUnmappedException(rootCause, ex));
    }

    private AuthFailureReason handleUnmappedException(Throwable rootCause, Throwable original) {
        log.warn(
                "Unmapped exception type for audit: {} (original: {})",
                rootCause.getClass().getName(),
                original.getClass().getName()
        );
        return AuthFailureReason.SYSTEM_ERROR;
    }
}