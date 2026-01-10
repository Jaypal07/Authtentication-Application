package com.jaypal.authapp.audit.domain;

public enum AuditSeverity {
    LOW,        // expected noise, invalid credentials
    MEDIUM,     // suspicious but common
    HIGH,       // security relevant
    CRITICAL    // compromise or system failure
}
