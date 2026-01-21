package com.jaypal.authapp.infrastructure.audit.resolver.mapping;

import com.jaypal.authapp.domain.audit.entity.AuthFailureReason;
import com.jaypal.authapp.exception.auth.*;
import com.jaypal.authapp.infrastructure.audit.resolver.ExceptionMappingStrategy;
import org.springframework.stereotype.Component;

@Component
public class PasswordExceptionMappingStrategy implements ExceptionMappingStrategy {

    @Override
    public boolean supports(Throwable throwable) {
        return throwable instanceof PasswordPolicyViolationException ||
                throwable instanceof PasswordResetTokenInvalidException ||
                throwable instanceof PasswordResetTokenExpiredException ||
                throwable instanceof PasswordResetTokenUsedException ||
                throwable instanceof org.springframework.security.authentication.CredentialsExpiredException;
    }

    @Override
    public AuthFailureReason mapToFailureReason(Throwable throwable) {
        if (throwable instanceof PasswordPolicyViolationException ||
                throwable instanceof org.springframework.security.authentication.CredentialsExpiredException) {
            return AuthFailureReason.PASSWORD_POLICY_VIOLATION;
        }

        if (throwable instanceof PasswordResetTokenInvalidException) {
            return AuthFailureReason.PASSWORD_RESET_TOKEN_INVALID;
        }

        if (throwable instanceof PasswordResetTokenExpiredException) {
            return AuthFailureReason.PASSWORD_RESET_TOKEN_EXPIRED;
        }

        if (throwable instanceof PasswordResetTokenUsedException) {
            return AuthFailureReason.PASSWORD_RESET_TOKEN_USED;
        }

        throw new IllegalStateException("Unsupported exception type: " + throwable.getClass());
    }
}