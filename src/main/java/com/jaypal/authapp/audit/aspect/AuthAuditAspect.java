package com.jaypal.authapp.audit.aspect;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.context.AuditContext;
import com.jaypal.authapp.audit.model.*;
import com.jaypal.authapp.audit.service.AuthAuditService;
import com.jaypal.authapp.auth.dto.AuthLoginResult;
import com.jaypal.authapp.auth.dto.TokenResponse;
import com.jaypal.authapp.exception.email.EmailAlreadyVerifiedException;
import com.jaypal.authapp.exception.email.EmailNotRegisteredException;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.*;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Aspect
@Component
@RequiredArgsConstructor
public class AuthAuditAspect {

    private final AuthAuditService auditService;
    private final HttpServletRequest request;

    // ---------- SUCCESS ----------

    @AfterReturning(
            pointcut = "@annotation(authAudit)",
            returning = "result"
    )
    public void auditSuccess(
            JoinPoint jp,
            AuthAudit authAudit,
            Object result
    ) {
        try {
            UUID userId = AuditContext.getUserId();
            if (userId == null) {
                userId = extractUserIdFromContext();
            }
            if (userId == null) {
                userId = extractUserId(result);
            }

            auditService.log(
                    userId,
                    extractSubject(authAudit, jp.getArgs()),
                    authAudit.event(),
                    authAudit.provider(),
                    request,
                    true,
                    null
            );
        } finally {
            AuditContext.clear();
        }
    }

    // ---------- FAILURE ----------

    @AfterThrowing(
            pointcut = "@annotation(authAudit)",
            throwing = "ex"
    )
    public void auditFailure(
            JoinPoint jp,
            AuthAudit authAudit,
            Throwable ex
    ) {
        try {
            AuthAuditEvent event = mapFailureEvent(authAudit.event());
            AuthFailureReason reason = resolveFailureReason(event, ex);

            auditService.log(
                    extractUserIdFromContext(),
                    extractSubject(authAudit, jp.getArgs()),
                    event,
                    authAudit.provider(),
                    request,
                    false,
                    reason
            );
        } finally {
            AuditContext.clear();
        }
    }

    // ---------- SUBJECT ----------

    private String extractSubject(AuthAudit authAudit, Object[] args) {

        // LOGIN FAILURE MUST LOG EMAIL
        if (authAudit.event() == AuthAuditEvent.LOGIN_SUCCESS) {
            for (Object arg : args) {
                if (arg instanceof HasEmail e) {
                    return e.getEmail();
                }
            }
        }

        if (authAudit.subject() == AuditSubjectType.EMAIL) {
            for (Object arg : args) {
                if (arg instanceof HasEmail e) {
                    return e.getEmail();
                }
            }
            return AuditContext.getEmail();
        }

        return null;
    }

    // ---------- EVENT MAPPING ----------

    private AuthAuditEvent mapFailureEvent(AuthAuditEvent successEvent) {
        return switch (successEvent) {
            case LOGIN_SUCCESS -> AuthAuditEvent.LOGIN_FAILURE;
            case OAUTH_LOGIN_SUCCESS -> AuthAuditEvent.OAUTH_LOGIN_FAILURE;
            case PASSWORD_RESET_SUCCESS -> AuthAuditEvent.PASSWORD_RESET_FAILURE;
            default -> successEvent;
        };
    }

    // ---------- FAILURE REASONS ----------

    private AuthFailureReason resolveFailureReason(
            AuthAuditEvent event,
            Throwable ex
    ) {

        // LOGIN
        if (event == AuthAuditEvent.LOGIN_FAILURE
                || event == AuthAuditEvent.OAUTH_LOGIN_FAILURE) {

            if (ex instanceof BadCredentialsException) {
                return AuthFailureReason.INVALID_CREDENTIALS;
            }
            if (ex instanceof DisabledException) {
                return AuthFailureReason.ACCOUNT_DISABLED;
            }
            if (ex instanceof LockedException) {
                return AuthFailureReason.ACCOUNT_LOCKED;
            }
        }

        // REGISTER
        if (event == AuthAuditEvent.REGISTER) {

            if (ex instanceof DataIntegrityViolationException) {
                return AuthFailureReason.EMAIL_ALREADY_EXISTS;
            }
            if (ex instanceof IllegalArgumentException) {
                return AuthFailureReason.VALIDATION_FAILED;
            }
        }

        // EMAIL VERIFY
        if (event == AuthAuditEvent.EMAIL_VERIFY) {

            if (ex instanceof ExpiredJwtException) {
                return AuthFailureReason.TOKEN_EXPIRED;
            }
            if (ex instanceof JwtException || ex instanceof IllegalArgumentException) {
                return AuthFailureReason.TOKEN_INVALID;
            }
            if (ex instanceof EmailAlreadyVerifiedException) {
                return AuthFailureReason.EMAIL_ALREADY_VERIFIED;
            }
        }

        // TOKEN
        if (event == AuthAuditEvent.TOKEN_REFRESH
                || event == AuthAuditEvent.TOKEN_ROTATION) {

            if (ex instanceof ExpiredJwtException) {
                return AuthFailureReason.TOKEN_EXPIRED;
            }
            if (ex instanceof JwtException || ex instanceof IllegalArgumentException) {
                return AuthFailureReason.TOKEN_INVALID;
            }
        }

        // PASSWORD RESET
        if (event == AuthAuditEvent.PASSWORD_RESET_FAILURE) {

            if (ex instanceof ExpiredJwtException) {
                return AuthFailureReason.RESET_TOKEN_EXPIRED;
            }
            if (ex instanceof JwtException || ex instanceof IllegalArgumentException) {
                return AuthFailureReason.RESET_TOKEN_INVALID;
            }
        }

        // PASSWORD CHANGE
        if (event == AuthAuditEvent.PASSWORD_CHANGE) {

            if (ex instanceof BadCredentialsException) {
                return AuthFailureReason.INVALID_CREDENTIALS;
            }
            if (ex instanceof IllegalArgumentException) {
                return AuthFailureReason.PASSWORD_POLICY_VIOLATION;
            }
        }

        // EMAIL RESEND
        if (event == AuthAuditEvent.EMAIL_VERIFICATION_RESEND) {

            if (ex instanceof EmailNotRegisteredException) {
                return AuthFailureReason.EMAIL_NOT_REGISTERED;
            }
            if (ex instanceof EmailAlreadyVerifiedException) {
                return AuthFailureReason.EMAIL_ALREADY_VERIFIED;
            }
        }

        return AuthFailureReason.SYSTEM_ERROR;
    }

    // ---------- USER ID ----------

    private UUID extractUserId(Object result) {

        if (result instanceof ResponseEntity<?> response) {
            Object body = response.getBody();
            if (body instanceof TokenResponse tokenResponse) {
                return tokenResponse.user().id();
            }
        }

        if (result instanceof AuthLoginResult authResult) {
            return authResult.user().getId();
        }

        return null;
    }

    private UUID extractUserIdFromContext() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof AuthPrincipal principal) {
            return principal.getUserId();
        }
        return null;
    }
}
