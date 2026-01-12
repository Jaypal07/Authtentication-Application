package com.jaypal.authapp.audit.resolver;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.domain.AuditSubject;
import com.jaypal.authapp.audit.domain.AuditSubjectType;
import com.jaypal.authapp.audit.domain.HasEmail;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Slf4j
@Component
public class SubjectResolver {

    public AuditSubject resolve(
            AuthAudit annotation,
            Object[] args,
            String[] paramNames
    ) {
        Objects.requireNonNull(annotation, "Annotation cannot be null");
        Objects.requireNonNull(args, "Arguments cannot be null");
        Objects.requireNonNull(paramNames, "Parameter names cannot be null");

        final AuditSubjectType type = annotation.subject();

        if (type == AuditSubjectType.ANONYMOUS) {
            return AuditSubject.anonymous();
        }

        if (type == AuditSubjectType.SYSTEM) {
            return AuditSubject.system();
        }

        if (annotation.subjectParam().isBlank()) {
            throw new IllegalStateException(
                    "subjectParam is required for subject type: " + type
            );
        }

        for (int i = 0; i < paramNames.length; i++) {
            if (annotation.subjectParam().equals(paramNames[i])) {
                final Object value = args[i];

                if (value == null) {
                    log.warn("Audit subject parameter is null: {}", paramNames[i]);
                    return AuditSubject.anonymous();
                }

                return extractSubject(type, value);
            }
        }

        throw new IllegalStateException(
                "Audit subject parameter not found: " + annotation.subjectParam()
        );
    }

    private AuditSubject extractSubject(AuditSubjectType type, Object value) {
        return switch (type) {
            case EMAIL -> extractEmail(value);
            case USER_ID -> extractUserId(value);
            case ANONYMOUS, SYSTEM -> throw new IllegalStateException(
                    "Type " + type + " should not require parameter extraction"
            );
        };
    }

    private AuditSubject extractEmail(Object value) {
        if (value instanceof String email) {
            return AuditSubject.email(email);
        }

        if (value instanceof HasEmail hasEmail) {
            return AuditSubject.email(hasEmail.getEmail());
        }

        if (value instanceof AuthPrincipal principal) {
            return AuditSubject.email(principal.getEmail());
        }

        log.warn("Cannot extract email from type: {}", value.getClass().getName());
        throw new IllegalStateException(
                "Cannot extract email from type: " + value.getClass().getName()
        );
    }

    private AuditSubject extractUserId(Object value) {
        if (value instanceof String userId) {
            return AuditSubject.userId(userId);
        }

        if (value instanceof AuthPrincipal principal) {
            return AuditSubject.userId(principal.getUserId().toString());
        }

        log.warn("Cannot extract user ID from type: {}", value.getClass().getName());
        throw new IllegalStateException(
                "Cannot extract user ID from type: " + value.getClass().getName()
        );
    }
}

/*
CHANGELOG:
1. CRITICAL FIX: Replaced unsafe toString() with type-safe extraction
2. Added support for HasEmail interface
3. Added support for AuthPrincipal
4. Added null check returns ANONYMOUS instead of throwing
5. Added comprehensive null checks for all parameters
6. Extracted subject extraction to dedicated methods
7. Added logging for unsupported types
8. Made error messages more descriptive
9. Used switch expression for type handling
*/