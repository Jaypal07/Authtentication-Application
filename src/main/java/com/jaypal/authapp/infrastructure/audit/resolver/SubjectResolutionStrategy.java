package com.jaypal.authapp.infrastructure.audit.resolver;

import com.jaypal.authapp.domain.audit.entity.AuditSubject;
import com.jaypal.authapp.domain.audit.entity.AuditSubjectType;

/**
 * Strategy interface for resolving audit subjects from various sources.
 * Follows Strategy Pattern for extensibility.
 */
public interface SubjectResolutionStrategy {
    boolean supports(AuditSubjectType type, Object value);
    AuditSubject resolve(Object value);
}