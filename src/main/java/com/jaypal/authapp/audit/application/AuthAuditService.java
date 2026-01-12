package com.jaypal.authapp.audit.application;

import com.jaypal.authapp.audit.domain.*;
import com.jaypal.authapp.audit.persistence.AuthAuditLog;
import com.jaypal.authapp.audit.persistence.AuthAuditRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthAuditService {

    private final AuthAuditRepository repository;
    private final AuditFailureMonitor failureMonitor;

    @Async("auditExecutor")
    public void record(
            AuditCategory category,
            AuthAuditEvent event,
            AuditOutcome outcome,
            AuditSubject subject,
            AuthFailureReason failureReason,
            AuthProvider provider,
            AuditRequestContext context
    ) {
        try {
            enforceInvariants(outcome, failureReason, subject, category, event, provider);

            final AuthAuditLog log = new AuthAuditLog(
                    category,
                    event,
                    outcome,
                    determineSeverity(outcome, failureReason),
                    subject,
                    failureReason,
                    provider,
                    context
            );

            repository.save(log);

            if (outcome == AuditOutcome.FAILURE && failureReason != null &&
                    failureReason.getSeverity() == AuditSeverity.CRITICAL) {
                log.warn("CRITICAL security event logged: event={}, subject={}, reason={}, ip={}",
                        event, subject.getType(), failureReason,
                        context != null ? context.ipAddress() : "N/A");
            }

        } catch (Exception ex) {
            failureMonitor.onAuditFailure(event, ex);
        }
    }

    private void enforceInvariants(
            AuditOutcome outcome,
            AuthFailureReason failureReason,
            AuditSubject subject,
            AuditCategory category,
            AuthAuditEvent event,
            AuthProvider provider
    ) {
        Objects.requireNonNull(category, "Category cannot be null");
        Objects.requireNonNull(event, "Event cannot be null");
        Objects.requireNonNull(outcome, "Outcome cannot be null");
        Objects.requireNonNull(subject, "Subject cannot be null");
        Objects.requireNonNull(provider, "Provider cannot be null");

        if (outcome == AuditOutcome.FAILURE && failureReason == null) {
            throw new IllegalArgumentException(
                    "Failure outcome must include reason for event: " + event);
        }

        if (outcome == AuditOutcome.SUCCESS && failureReason != null) {
            throw new IllegalArgumentException(
                    "Success outcome must not include failure reason for event: " + event);
        }
    }

    private AuditSeverity determineSeverity(
            AuditOutcome outcome,
            AuthFailureReason failureReason
    ) {
        if (outcome == AuditOutcome.SUCCESS) {
            return AuditSeverity.LOW;
        }

        return failureReason != null ? failureReason.getSeverity() : AuditSeverity.MEDIUM;
    }
}

/*
CHANGELOG:
1. Added null checks for all required parameters
2. Added logging for CRITICAL severity events
3. Extracted severity determination to separate method
4. Improved error messages with event context
5. Added IP address to critical event logs (when available)
6. Made invariant enforcement more descriptive
7. Context parameter now properly used (not always null)
*/