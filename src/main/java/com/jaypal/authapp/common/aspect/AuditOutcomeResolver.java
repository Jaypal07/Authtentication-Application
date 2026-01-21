package com.jaypal.authapp.common.aspect;

import com.jaypal.authapp.domain.audit.entity.AuditOutcome;
import com.jaypal.authapp.infrastructure.audit.context.AuditContextHolder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Dedicated component for outcome determination.
 * Follows Single Responsibility Principle.
 */
@Slf4j
@Component
public class AuditOutcomeResolver {

    public AuditOutcome determineOutcome(Object result) {
        // Context-level NO_OP (business decision)
        if (AuditContextHolder.isNoOp()) {
            log.debug("Audit outcome overridden to NO_OP via AuditContextHolder");
            return AuditOutcome.NO_OP;
        }

        // Return-based NO_OP
        if (result == null) {
            return AuditOutcome.NO_OP;
        }

        if (result instanceof Boolean b && !b) {
            return AuditOutcome.NO_OP;
        }

        return AuditOutcome.SUCCESS;
    }
}