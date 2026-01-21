package com.jaypal.authapp.domain.audit.service;

import com.jaypal.authapp.domain.audit.entity.AuditOutcome;
import com.jaypal.authapp.domain.audit.entity.AuditSeverity;
import com.jaypal.authapp.domain.audit.entity.AuthFailureReason;
import org.springframework.stereotype.Component;

/**
 * Dedicated component for calculating audit severity.
 * Follows Single Responsibility Principle.
 */
@Component
public class AuditSeverityCalculator {

    public AuditSeverity calculate(AuditOutcome outcome, AuthFailureReason failureReason) {
        return switch (outcome) {
            case SUCCESS, NO_OP -> AuditSeverity.LOW;
            case FAILURE -> calculateFailureSeverity(failureReason);
        };
    }

    private AuditSeverity calculateFailureSeverity(AuthFailureReason failureReason) {
        return failureReason != null
                ? failureReason.getSeverity()
                : AuditSeverity.MEDIUM;
    }
}
