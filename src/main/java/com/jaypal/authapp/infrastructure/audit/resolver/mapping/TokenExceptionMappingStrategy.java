package com.jaypal.authapp.infrastructure.audit.resolver.mapping;

import com.jaypal.authapp.domain.audit.entity.AuthFailureReason;
import com.jaypal.authapp.domain.token.exception.*;
import com.jaypal.authapp.exception.auth.*;
import com.jaypal.authapp.infrastructure.audit.resolver.ExceptionMappingStrategy;
import org.springframework.stereotype.Component;

@Component
public class TokenExceptionMappingStrategy implements ExceptionMappingStrategy {

    @Override
    public boolean supports(Throwable throwable) {
        return throwable instanceof MissingRefreshTokenException ||
                throwable instanceof RefreshTokenExpiredException ||
                throwable instanceof VerificationTokenExpiredException ||
                throwable instanceof RefreshTokenRevokedException ||
                throwable instanceof InvalidRefreshTokenException ||
                throwable instanceof VerificationTokenInvalidException ||
                throwable instanceof RefreshTokenReuseDetectedException;
    }

    @Override
    public AuthFailureReason mapToFailureReason(Throwable throwable) {
        if (throwable instanceof MissingRefreshTokenException) {
            return AuthFailureReason.TOKEN_MISSING;
        }

        if (throwable instanceof RefreshTokenExpiredException ||
                throwable instanceof VerificationTokenExpiredException) {
            return AuthFailureReason.TOKEN_EXPIRED;
        }

        if (throwable instanceof RefreshTokenRevokedException) {
            return AuthFailureReason.TOKEN_REVOKED;
        }

        if (throwable instanceof InvalidRefreshTokenException ||
                throwable instanceof VerificationTokenInvalidException) {
            return AuthFailureReason.TOKEN_INVALID;
        }

        if (throwable instanceof RefreshTokenReuseDetectedException) {
            return AuthFailureReason.TOKEN_REFRESH_REUSED;
        }

        throw new IllegalStateException("Unsupported exception type: " + throwable.getClass());
    }
}
