package com.jaypal.authapp.infrastructure.audit.resolver.mapping;

import com.jaypal.authapp.domain.audit.entity.AuthFailureReason;
import com.jaypal.authapp.domain.user.exception.EmailAlreadyExistsException;
import com.jaypal.authapp.exception.auth.EmailAlreadyVerifiedException;
import com.jaypal.authapp.exception.auth.EmailNotRegisteredException;
import com.jaypal.authapp.exception.auth.EmailNotVerifiedException;
import com.jaypal.authapp.infrastructure.audit.resolver.ExceptionMappingStrategy;
import org.springframework.stereotype.Component;

@Component
public class EmailExceptionMappingStrategy implements ExceptionMappingStrategy {

    @Override
    public boolean supports(Throwable throwable) {
        return throwable instanceof EmailAlreadyExistsException ||
                throwable instanceof EmailAlreadyVerifiedException ||
                throwable instanceof EmailNotRegisteredException ||
                throwable instanceof EmailNotVerifiedException;
    }

    @Override
    public AuthFailureReason mapToFailureReason(Throwable throwable) {
        if (throwable instanceof EmailAlreadyExistsException) {
            return AuthFailureReason.EMAIL_ALREADY_EXISTS;
        }

        if (throwable instanceof EmailAlreadyVerifiedException) {
            return AuthFailureReason.EMAIL_ALREADY_VERIFIED;
        }

        if (throwable instanceof EmailNotRegisteredException) {
            return AuthFailureReason.EMAIL_NOT_REGISTERED;
        }
        if (throwable instanceof EmailNotVerifiedException) {
            return AuthFailureReason.EMAIL_NOT_VERIFIED;
        }

        throw new IllegalStateException("Unsupported exception type: " + throwable.getClass());
    }
}
