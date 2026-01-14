package com.jaypal.authapp.audit.domain;

public enum AuthFailureReason {

    INVALID_CREDENTIALS(AuditSeverity.LOW),
    USER_NOT_FOUND(AuditSeverity.LOW),

    ACCOUNT_DISABLED(AuditSeverity.HIGH),
    ACCOUNT_LOCKED(AuditSeverity.HIGH),

    TOKEN_MISSING(AuditSeverity.MEDIUM),
    TOKEN_INVALID(AuditSeverity.HIGH),
    TOKEN_EXPIRED(AuditSeverity.MEDIUM),
    TOKEN_REVOKED(AuditSeverity.CRITICAL),

    EMAIL_ALREADY_EXISTS(AuditSeverity.LOW),
    EMAIL_ALREADY_VERIFIED(AuditSeverity.LOW),
    EMAIL_NOT_REGISTERED(AuditSeverity.LOW),


    VALIDATION_FAILED(AuditSeverity.LOW),

    RESET_TOKEN_INVALID(AuditSeverity.HIGH),
    RESET_TOKEN_EXPIRED(AuditSeverity.MEDIUM),
    ACCESS_DENIED(AuditSeverity.MEDIUM),

    PASSWORD_POLICY_VIOLATION(AuditSeverity.MEDIUM),
    RATE_LIMIT_EXCEEDED(AuditSeverity.MEDIUM),

    SYSTEM_ERROR(AuditSeverity.CRITICAL);

    private final AuditSeverity severity;

    AuthFailureReason(AuditSeverity severity) {
        this.severity = severity;
    }

    public AuditSeverity getSeverity() {
        return severity;
    }
}
