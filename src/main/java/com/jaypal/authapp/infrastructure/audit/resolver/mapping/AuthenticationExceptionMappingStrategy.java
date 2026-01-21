package com.jaypal.authapp.infrastructure.audit.resolver.mapping;

import com.jaypal.authapp.domain.audit.entity.AuthFailureReason;
import com.jaypal.authapp.infrastructure.audit.resolver.ExceptionMappingStrategy;
import org.springframework.security.authentication.*;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationExceptionMappingStrategy implements ExceptionMappingStrategy {

    @Override
    public boolean supports(Throwable throwable) {
        return throwable instanceof BadCredentialsException ||
                throwable instanceof UsernameNotFoundException ||
                throwable instanceof DisabledException ||
                throwable instanceof LockedException;
    }

    @Override
    public AuthFailureReason mapToFailureReason(Throwable throwable) {
        if (throwable instanceof BadCredentialsException ||
                throwable instanceof UsernameNotFoundException) {
            return AuthFailureReason.INVALID_CREDENTIALS;
        }

        if (throwable instanceof DisabledException) {
            return AuthFailureReason.ACCOUNT_DISABLED;
        }

        if (throwable instanceof LockedException) {
            return AuthFailureReason.ACCOUNT_LOCKED;
        }

        throw new IllegalStateException("Unsupported exception type: " + throwable.getClass());
    }
}
