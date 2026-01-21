package com.jaypal.authapp.infrastructure.audit.resolver;

import com.jaypal.authapp.common.annotation.AuthAudit;
import com.jaypal.authapp.domain.audit.entity.AuditSubject;
import com.jaypal.authapp.domain.audit.entity.AuditSubjectType;
import com.jaypal.authapp.infrastructure.audit.context.AuditContextHolder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Objects;

/**
 * Refactored SubjectResolver following SOLID principles:
 * - Single Responsibility: Orchestrates subject resolution
 * - Open/Closed: Extensible via strategy pattern
 * - Dependency Inversion: Depends on SubjectResolutionStrategy abstraction
 */
@Slf4j
@Component
public class SubjectResolver {

    private final List<SubjectResolutionStrategy> strategies;

    public SubjectResolver(List<SubjectResolutionStrategy> strategies) {
        this.strategies = Objects.requireNonNull(strategies, "strategies must not be null");
    }

    public AuditSubject resolve(AuthAudit annotation, Object[] args, String[] paramNames) {
        try {
            validateInputs(annotation, args, paramNames);

            AuditSubjectType type = annotation.subject();

            // Handle static subject types
            if (isStaticSubjectType(type)) {
                return resolveStaticSubject(type);
            }

            // Handle parameter-based resolution
            return resolveFromParameter(annotation, args, paramNames, type);

        } catch (Exception ex) {
            log.warn("Audit subject resolution failed, defaulting to ANONYMOUS", ex);
            return AuditSubject.anonymous();
        }
    }

    private void validateInputs(AuthAudit annotation, Object[] args, String[] paramNames) {
        Objects.requireNonNull(annotation, "annotation must not be null");
        Objects.requireNonNull(args, "args must not be null");
        Objects.requireNonNull(paramNames, "paramNames must not be null");
    }

    private boolean isStaticSubjectType(AuditSubjectType type) {
        return type == AuditSubjectType.ANONYMOUS || type == AuditSubjectType.SYSTEM;
    }

    private AuditSubject resolveStaticSubject(AuditSubjectType type) {
        return switch (type) {
            case ANONYMOUS -> AuditSubject.anonymous();
            case SYSTEM -> AuditSubject.system();
            default -> throw new IllegalStateException("Unexpected static type: " + type);
        };
    }

    private AuditSubject resolveFromParameter(
            AuthAudit annotation,
            Object[] args,
            String[] paramNames,
            AuditSubjectType type
    ) {
        // Special handling for USER_ID from context
        if (annotation.subjectParam().isBlank()) {
            if (type == AuditSubjectType.USER_ID) {
                return resolveUserIdFromContext();
            }
            log.warn("Audit subjectParam is blank for subject type {}", type);
            return AuditSubject.anonymous();
        }

        // Find and resolve from parameter
        for (int i = 0; i < paramNames.length; i++) {
            if (annotation.subjectParam().equals(paramNames[i])) {
                return resolveFromValue(type, args[i], paramNames[i]);
            }
        }

        log.warn("Audit subject parameter '{}' not found", annotation.subjectParam());
        return AuditSubject.anonymous();
    }

    private AuditSubject resolveFromValue(AuditSubjectType type, Object value, String paramName) {
        if (value == null) {
            if (type == AuditSubjectType.USER_ID) {
                return resolveUserIdFromContext();
            }
            log.warn("Audit subject parameter '{}' is null", paramName);
            return AuditSubject.anonymous();
        }

        return strategies.stream()
                .filter(strategy -> strategy.supports(type, value))
                .findFirst()
                .map(strategy -> strategy.resolve(value))
                .orElseGet(() -> {
                    log.warn("No strategy found for type {} and value {}", type, value.getClass().getName());
                    return AuditSubject.anonymous();
                });
    }

    private AuditSubject resolveUserIdFromContext() {
        try {
            var ctx = AuditContextHolder.getContext();

            if (ctx != null && ctx.userId() != null && !ctx.userId().isBlank()) {
                return AuditSubject.userId(ctx.userId());
            }

            log.debug("No userId found in AuditRequestContext, defaulting to ANONYMOUS");
            return AuditSubject.anonymous();

        } catch (Exception ex) {
            log.warn("Failed to resolve userId from AuditRequestContext", ex);
            return AuditSubject.anonymous();
        }
    }
}