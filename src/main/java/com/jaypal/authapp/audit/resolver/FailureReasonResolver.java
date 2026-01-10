package com.jaypal.authapp.audit.resolver;

import com.jaypal.authapp.audit.domain.AuthFailureReason;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.*;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class FailureReasonResolver {

    public AuthFailureReason resolve(Throwable ex) {

        if (ex instanceof BadCredentialsException)
            return AuthFailureReason.INVALID_CREDENTIALS;

        if (ex instanceof DisabledException)
            return AuthFailureReason.ACCOUNT_DISABLED;

        if (ex instanceof LockedException)
            return AuthFailureReason.ACCOUNT_LOCKED;

        if (ex instanceof CredentialsExpiredException)
            return AuthFailureReason.TOKEN_EXPIRED;

        if (ex instanceof IllegalArgumentException)
            return AuthFailureReason.VALIDATION_FAILED;

        log.error("UNMAPPED_AUTH_FAILURE", ex);
        return AuthFailureReason.SYSTEM_ERROR;
    }
}

