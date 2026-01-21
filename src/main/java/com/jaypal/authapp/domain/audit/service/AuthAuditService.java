package com.jaypal.authapp.domain.audit.service;

import com.jaypal.authapp.domain.audit.entity.*;
import com.jaypal.authapp.domain.audit.repository.AuthAuditRepository;
import com.jaypal.authapp.dto.audit.AuditRequestContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.Objects;

/**
 * Refactored AuthAuditService with improved validation and clarity.
 * Separated concerns into smaller, focused methods.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthAuditService {

    private final AuthAuditRepository repository;
    private final AuditFailureMonitor failureMonitor;
    private final AuditInvariantValidator invariantValidator;
    private final AuditSeverityCalculator severityCalculator;

    @Async("auditExecutor")
    public void record(
            AuditCategory category,
            AuthAuditEvent event,
            AuditOutcome outcome,
            AuditActor actor,
            AuditSubject subject,
            AuthFailureReason failureReason,
            AuthProvider provider,
            AuditRequestContext context,
            String details
    ) {
        try {
            logAuditInvocation(category, event, outcome, actor, subject, failureReason, provider);

            invariantValidator.validate(category, event, outcome, subject, failureReason, provider);

            AuditSeverity severity = severityCalculator.calculate(outcome, failureReason);

            AuthAuditLog auditLog = createAuditLog(
                    category, event, outcome, severity, actor, subject,
                    failureReason, provider, context, details
            );

            AuthAuditLog saved = repository.save(auditLog);

            logAuditPersisted(saved, event, outcome, severity);

        } catch (Exception ex) {
            handleAuditFailure(event, outcome, subject, provider, ex);
        }
    }

    @Async("auditExecutor")
    public void record(
            AuditCategory category,
            AuthAuditEvent event,
            AuditOutcome outcome,
            AuditActor actor,
            AuditSubject subject,
            AuthFailureReason failureReason,
            AuthProvider provider,
            AuditRequestContext context
    ) {
        record(category, event, outcome, actor, subject, failureReason, provider, context, null);
    }

    private void logAuditInvocation(
            AuditCategory category,
            AuthAuditEvent event,
            AuditOutcome outcome,
            AuditActor actor,
            AuditSubject subject,
            AuthFailureReason failureReason,
            AuthProvider provider
    ) {
        if (log.isDebugEnabled()) {
            log.debug(
                    "AUDIT invoked | thread={} category={} event={} outcome={} actor={} subject={} failureReason={} provider={}",
                    Thread.currentThread().getName(),
                    category,
                    event,
                    outcome,
                    actor,
                    subject,
                    failureReason,
                    provider
            );
        }
    }

    private AuthAuditLog createAuditLog(
            AuditCategory category,
            AuthAuditEvent event,
            AuditOutcome outcome,
            AuditSeverity severity,
            AuditActor actor,
            AuditSubject subject,
            AuthFailureReason failureReason,
            AuthProvider provider,
            AuditRequestContext context,
            String details
    ) {
        return new AuthAuditLog(
                category,
                event,
                outcome,
                severity,
                actor,
                subject,
                failureReason,
                provider,
                context,
                details
        );
    }

    private void logAuditPersisted(
            AuthAuditLog saved,
            AuthAuditEvent event,
            AuditOutcome outcome,
            AuditSeverity severity
    ) {
        log.info(
                "AUDIT persisted | auditId={} event={} outcome={} severity={}",
                saved.getId(),
                event,
                outcome,
                severity
        );

        if (outcome == AuditOutcome.FAILURE && severity == AuditSeverity.CRITICAL) {
            log.warn(
                    "AUDIT CRITICAL | auditId={} event={} severity={}",
                    saved.getId(),
                    event,
                    severity
            );
        }
    }

    private void handleAuditFailure(
            AuthAuditEvent event,
            AuditOutcome outcome,
            AuditSubject subject,
            AuthProvider provider,
            Exception ex
    ) {
        log.error(
                "AUDIT FAILED | event={} outcome={} subject={} provider={}",
                event,
                outcome,
                subject,
                provider,
                ex
        );
        failureMonitor.onAuditFailure(event, ex);
    }
}