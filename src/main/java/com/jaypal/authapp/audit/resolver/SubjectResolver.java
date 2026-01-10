package com.jaypal.authapp.audit.resolver;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.domain.AuditSubject;
import com.jaypal.authapp.audit.domain.AuditSubjectType;
import org.springframework.stereotype.Component;

@Component
public class SubjectResolver {

    public AuditSubject resolve(AuthAudit annotation) {
        return switch (annotation.subject()) {
            case ANONYMOUS -> AuditSubject.anonymous();
            case SYSTEM -> AuditSubject.system();
            default -> throw new IllegalStateException(
                    "Subject must be resolved explicitly for " + annotation.subject()
            );
        };
    }
}
