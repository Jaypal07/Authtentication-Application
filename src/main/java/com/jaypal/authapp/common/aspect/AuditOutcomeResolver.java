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

        // 1️⃣ Explicit business FAILURE (highest priority)
        if (AuditContextHolder.isFailure()) {
            log.debug(
                    "Audit outcome overridden to FAILURE via AuditContextHolder, reason={}",
                    AuditContextHolder.getFailureReason()
            );
            return AuditOutcome.FAILURE;
        }

        // 2️⃣ Explicit business NO_OP
        if (AuditContextHolder.isNoOp()) {
            log.debug("Audit outcome overridden to NO_OP via AuditContextHolder");
            return AuditOutcome.NO_OP;
        }

        // 3️⃣ Return-based NO_OP (legacy / safety)
        if (result == null) {
            return AuditOutcome.NO_OP;
        }

        if (result instanceof Boolean b && !b) {
            return AuditOutcome.NO_OP;
        }

        // 4️⃣ Default success
        return AuditOutcome.SUCCESS;
    }
}
