package com.jaypal.authapp.domain.audit.service;

import com.jaypal.authapp.domain.audit.entity.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Objects;

/**
 * Dedicated component for validating audit invariants.
 * Extracted for better testability and reusability.
 */
@Slf4j
@Component
public class AuditInvariantValidator {

    public void validate(
            AuditCategory category,
            AuthAuditEvent event,
            AuditOutcome outcome,
            AuditSubject subject,
            AuthFailureReason failureReason,
            AuthProvider provider
    ) {
        Objects.requireNonNull(category, "Audit category must not be null");
        Objects.requireNonNull(event, "Audit event must not be null");
        Objects.requireNonNull(outcome, "Audit outcome must not be null");
        Objects.requireNonNull(subject, "Audit subject must not be null");
        Objects.requireNonNull(provider, "Auth provider must not be null");

        validateFailureReasonConsistency(event, outcome, failureReason);

        if (log.isDebugEnabled()) {
            log.debug("AUDIT invariants validated | event={} outcome={}", event, outcome);
        }
    }

    private void validateFailureReasonConsistency(
            AuthAuditEvent event,
            AuditOutcome outcome,
            AuthFailureReason failureReason
    ) {
        if (outcome == AuditOutcome.FAILURE && failureReason == null) {
            throw new IllegalArgumentException(
                    "Failure outcome requires failureReason for event: " + event
            );
        }
        if (outcome == AuditOutcome.REJECTION && failureReason == null) {
            throw new IllegalArgumentException(
                    "Rejection outcome requires failureReason for event: " + event
            );
        }

        if (outcome == AuditOutcome.SUCCESS && failureReason != null) {
            throw new IllegalArgumentException(
                    "Success outcome must not include failureReason for event: " + event
            );
        }
    }
}