package com.jaypal.authapp.audit.resolver;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.domain.AuditSubject;
import com.jaypal.authapp.audit.domain.AuditSubjectType;
import org.springframework.stereotype.Component;

@Component
public class SubjectResolver {

    public AuditSubject resolve(
            AuthAudit annotation,
            Object[] args,
            String[] paramNames
    ) {
        AuditSubjectType type = annotation.subject();

        if (type == AuditSubjectType.ANONYMOUS) {
            return AuditSubject.anonymous();
        }

        if (type == AuditSubjectType.SYSTEM) {
            return AuditSubject.system();
        }

        if (annotation.subjectParam().isBlank()) {
            throw new IllegalStateException(
                    "subjectParam is required for subject type " + type
            );
        }

        for (int i = 0; i < paramNames.length; i++) {
            if (annotation.subjectParam().equals(paramNames[i])) {
                Object value = args[i];
                if (value == null) {
                    throw new IllegalStateException(
                            "Audit subject parameter is null: " + paramNames[i]
                    );
                }

                return switch (type) {
                    case EMAIL -> AuditSubject.email(value.toString());
                    case USER_ID -> AuditSubject.userId(value.toString());
                    default -> throw new IllegalStateException("Unsupported subject type");
                };
            }
        }

        throw new IllegalStateException(
                "Audit subject parameter not found: " + annotation.subjectParam()
        );
    }
}
