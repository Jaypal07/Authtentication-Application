package com.jaypal.authapp.infrastructure.audit.resolver.strategy;

import com.jaypal.authapp.domain.audit.entity.AuditSubject;
import com.jaypal.authapp.domain.audit.entity.AuditSubjectType;
import com.jaypal.authapp.domain.audit.entity.HasEmail;
import com.jaypal.authapp.infrastructure.audit.resolver.SubjectResolutionStrategy;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class EmailResolutionStrategy implements SubjectResolutionStrategy {

    @Override
    public boolean supports(AuditSubjectType type, Object value) {
        return type == AuditSubjectType.EMAIL &&
                (value instanceof String ||
                        value instanceof HasEmail ||
                        value instanceof AuthPrincipal);
    }

    @Override
    public AuditSubject resolve(Object value) {
        try {
            String email = extractEmail(value);

            if (email == null || email.isBlank()) {
                log.warn("Extracted email is blank from type: {}", value.getClass().getName());
                return AuditSubject.anonymous();
            }

            return AuditSubject.email(email);

        } catch (Exception ex) {
            log.warn("Email extraction failed, defaulting to ANONYMOUS", ex);
            return AuditSubject.anonymous();
        }
    }

    private String extractEmail(Object value) {
        if (value instanceof String str) {
            return str;
        }

        if (value instanceof HasEmail hasEmail) {
            return hasEmail.getEmail();
        }

        if (value instanceof AuthPrincipal principal) {
            return principal.getEmail();
        }

        log.warn("Cannot extract email from type: {}", value.getClass().getName());
        return null;
    }
}