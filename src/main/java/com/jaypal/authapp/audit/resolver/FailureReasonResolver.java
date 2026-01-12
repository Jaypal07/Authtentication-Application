package com.jaypal.authapp.audit.resolver;

import com.jaypal.authapp.audit.domain.AuthFailureReason;
import com.jaypal.authapp.auth.exception.*;
import com.jaypal.authapp.token.exception.*;
import com.jaypal.authapp.user.exception.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.*;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.util.Objects;

@Slf4j
@Component
public class FailureReasonResolver {

    public AuthFailureReason resolve(Throwable ex) {
        Objects.requireNonNull(ex, "Exception cannot be null");

        if (ex instanceof BadCredentialsException ||
                ex instanceof InvalidCredentialsException ||
                ex instanceof UsernameNotFoundException) {
            return AuthFailureReason.INVALID_CREDENTIALS;
        }

        if (ex instanceof DisabledException ||
                ex instanceof UserAccountDisabledException) {
            return AuthFailureReason.ACCOUNT_DISABLED;
        }

        if (ex instanceof LockedException) {
            return AuthFailureReason.ACCOUNT_LOCKED;
        }

        if (ex instanceof RefreshTokenExpiredException ||
                ex instanceof PasswordResetTokenExpiredException ||
                ex instanceof VerificationTokenExpiredException ||
                ex instanceof CredentialsExpiredException) {
            return AuthFailureReason.TOKEN_EXPIRED;
        }

        if (ex instanceof RefreshTokenRevokedException) {
            return AuthFailureReason.TOKEN_REVOKED;
        }

        if (ex instanceof RefreshTokenNotFoundException ||
                ex instanceof InvalidRefreshTokenException ||
                ex instanceof PasswordResetTokenInvalidException ||
                ex instanceof VerificationTokenInvalidException) {
            return AuthFailureReason.TOKEN_INVALID;
        }

        if (ex instanceof MissingRefreshTokenException) {
            return AuthFailureReason.TOKEN_MISSING;
        }

        if (ex instanceof EmailAlreadyExistsException ||
                ex instanceof DataIntegrityViolationException) {
            return AuthFailureReason.EMAIL_ALREADY_EXISTS;
        }

        if (ex instanceof EmailAlreadyVerifiedException) {
            return AuthFailureReason.EMAIL_ALREADY_VERIFIED;
        }

        if (ex instanceof EmailNotRegisteredException) {
            return AuthFailureReason.EMAIL_NOT_REGISTERED;
        }

        if (ex instanceof PasswordPolicyViolationException) {
            return AuthFailureReason.PASSWORD_POLICY_VIOLATION;
        }

        if (ex instanceof PasswordResetTokenInvalidException) {
            return AuthFailureReason.RESET_TOKEN_INVALID;
        }

        if (ex instanceof PasswordResetTokenExpiredException) {
            return AuthFailureReason.RESET_TOKEN_EXPIRED;
        }

        if (ex instanceof AccessDeniedException) {
            return AuthFailureReason.ACCESS_DENIED;
        }

        if (ex instanceof MethodArgumentNotValidException ||
                ex instanceof IllegalArgumentException) {
            return AuthFailureReason.VALIDATION_FAILED;
        }

        if (ex instanceof ResourceNotFoundException ||
                ex instanceof AuthenticatedUserMissingException) {
            return AuthFailureReason.USER_NOT_FOUND;
        }

        log.warn("Unmapped exception type for audit: {}", ex.getClass().getName());
        return AuthFailureReason.SYSTEM_ERROR;
    }
}

/*
CHANGELOG:
1. Added comprehensive exception mapping for all IAM exceptions
2. Added null check for exception parameter
3. Grouped related exceptions together for clarity
4. Added all token-related exceptions (refresh, password reset, verification)
5. Added all authentication exceptions
6. Added all authorization exceptions
7. Added validation exceptions
8. Improved logging for unmapped exceptions
9. Made exception class name visible in logs for debugging
*/