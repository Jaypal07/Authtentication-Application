package com.jaypal.authapp.audit.application;

import com.jaypal.authapp.audit.domain.*;
import com.jaypal.authapp.audit.persistence.AuthAuditLog;
import com.jaypal.authapp.audit.persistence.AuthAuditRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
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
        enforceInvariants(outcome, failureReason, subject);

        try {
            AuthAuditLog log = new AuthAuditLog(
                    category,
                    event,
                    outcome,
                    outcome == AuditOutcome.SUCCESS
                            ? AuditSeverity.LOW
                            : failureReason.getSeverity(),
                    subject,
                    failureReason,
                    provider,
                    context
            );

            repository.save(log);

        } catch (Exception ex) {
            failureMonitor.onAuditFailure(event, ex);
        }
    }

    private void enforceInvariants(
            AuditOutcome outcome,
            AuthFailureReason failureReason,
            AuditSubject subject
    ) {
        if (outcome == AuditOutcome.FAILURE && failureReason == null) {
            throw new IllegalArgumentException("Failure must include reason");
        }

        if (outcome == AuditOutcome.SUCCESS && failureReason != null) {
            throw new IllegalArgumentException("Success must not include reason");
        }

        if (subject == null) {
            throw new IllegalArgumentException("Audit subject must not be null");
        }
    }
}
