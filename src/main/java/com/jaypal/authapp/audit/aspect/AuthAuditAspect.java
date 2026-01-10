package com.jaypal.authapp.audit.aspect;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.application.AuthAuditService;
import com.jaypal.authapp.audit.domain.*;
import com.jaypal.authapp.audit.resolver.FailureReasonResolver;
import com.jaypal.authapp.audit.resolver.IdentityResolver;
import com.jaypal.authapp.audit.resolver.SubjectResolver;
import lombok.RequiredArgsConstructor;
import org.aspectj.lang.annotation.*;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Aspect
@Component
@RequiredArgsConstructor
public class AuthAuditAspect {

    private final AuthAuditService auditService;
    private final FailureReasonResolver failureResolver;
    private final IdentityResolver identityResolver;
    private final SubjectResolver subjectResolver;

    @AfterReturning(pointcut = "@annotation(authAudit)", returning = "result")
    public void success(AuthAudit authAudit, Object result) {

        AuditSubject subject = resolveSubject(authAudit, result);

        auditService.record(
                resolveCategory(authAudit.event()),
                authAudit.event(),
                AuditOutcome.SUCCESS,
                subject,
                null,
                authAudit.provider(),
                null
        );
    }

    @AfterThrowing(pointcut = "@annotation(authAudit)", throwing = "ex")
    public void failure(AuthAudit authAudit, Throwable ex) {

        AuthFailureReason reason = failureResolver.resolve(ex);
        AuditSubject subject = resolveSubject(authAudit, null);

        auditService.record(
                resolveCategory(authAudit.event()),
                authAudit.event(),
                AuditOutcome.FAILURE,
                subject,
                reason,
                authAudit.provider(),
                null
        );
    }

    private AuditSubject resolveSubject(AuthAudit authAudit, Object result) {

        UUID userId = identityResolver.fromSecurityContext();
        if (userId != null) return AuditSubject.userId(userId.toString());

        UUID fromResult = result != null ? identityResolver.fromResult(result) : null;
        if (fromResult != null) return AuditSubject.userId(fromResult.toString());

        return subjectResolver.resolve(authAudit);
    }

    private AuditCategory resolveCategory(AuthAuditEvent event) {
        return switch (event) {

            case LOGIN, LOGOUT, REGISTER,
                 EMAIL_VERIFY, EMAIL_VERIFICATION_RESEND,
                 OAUTH_LOGIN,
                 TOKEN_ISSUED, TOKEN_REFRESHED, TOKEN_REVOKED
                    -> AuditCategory.AUTHENTICATION;

            case PASSWORD_CHANGE,
                 PASSWORD_RESET_REQUEST,
                 PASSWORD_RESET_RESULT,
                 ACCOUNT_UPDATED,
                 ACCOUNT_DISABLED
                    -> AuditCategory.ACCOUNT;

            case ROLE_ASSIGNED,
                 ROLE_REMOVED,
                 PERMISSION_GRANTED,
                 PERMISSION_REVOKED
                    -> AuditCategory.AUTHORIZATION;

            case ADMIN_USER_CREATED,
                 ADMIN_USER_UPDATED,
                 ADMIN_USER_DELETED
                    -> AuditCategory.ADMIN;
        };
    }
}


