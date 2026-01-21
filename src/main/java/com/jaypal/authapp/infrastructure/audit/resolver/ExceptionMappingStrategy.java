package com.jaypal.authapp.infrastructure.audit.resolver;

import com.jaypal.authapp.domain.audit.entity.AuthFailureReason;

/**
 * Strategy interface for mapping exceptions to failure reasons.
 * Enables extensibility and testability.
 */
public interface ExceptionMappingStrategy {
    boolean supports(Throwable throwable);
    AuthFailureReason mapToFailureReason(Throwable throwable);
}