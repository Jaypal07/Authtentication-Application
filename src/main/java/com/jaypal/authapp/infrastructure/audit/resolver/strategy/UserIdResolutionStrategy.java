package com.jaypal.authapp.infrastructure.audit.resolver.strategy;

import com.jaypal.authapp.domain.audit.entity.AuditSubject;
import com.jaypal.authapp.domain.audit.entity.AuditSubjectType;
import com.jaypal.authapp.infrastructure.audit.resolver.SubjectResolutionStrategy;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class UserIdResolutionStrategy implements SubjectResolutionStrategy {

    @Override
    public boolean supports(AuditSubjectType type, Object value) {
        return type == AuditSubjectType.USER_ID &&
                (value instanceof String || value instanceof AuthPrincipal);
    }

    @Override
    public AuditSubject resolve(Object value) {
        try {
            String userId = extractUserId(value);

            if (userId == null || userId.isBlank()) {
                log.warn("Extracted user ID is blank from type: {}", value.getClass().getName());
                return AuditSubject.anonymous();
            }

            return AuditSubject.userId(userId);

        } catch (Exception ex) {
            log.warn("User ID extraction failed, defaulting to ANONYMOUS", ex);
            return AuditSubject.anonymous();
        }
    }

    private String extractUserId(Object value) {
        if (value instanceof String str) {
            return str;
        }

        if (value instanceof AuthPrincipal principal && principal.getUserId() != null) {
            return principal.getUserId().toString();
        }

        log.warn("Cannot extract user ID from type: {}", value.getClass().getName());
        return null;
    }
}
