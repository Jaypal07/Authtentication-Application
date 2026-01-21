package com.jaypal.authapp.infrastructure.audit.resolver.mapping;

import com.jaypal.authapp.domain.audit.entity.AuthFailureReason;
import com.jaypal.authapp.domain.user.exception.ResourceNotFoundException;
import com.jaypal.authapp.exception.auth.AuthenticatedUserMissingException;
import com.jaypal.authapp.infrastructure.audit.resolver.ExceptionMappingStrategy;
import org.springframework.stereotype.Component;

@Component
public class NotFoundExceptionMappingStrategy implements ExceptionMappingStrategy {

    @Override
    public boolean supports(Throwable throwable) {
        return throwable instanceof ResourceNotFoundException ||
                throwable instanceof AuthenticatedUserMissingException;
    }

    @Override
    public AuthFailureReason mapToFailureReason(Throwable throwable) {
        return AuthFailureReason.ADMIN_TARGET_NOT_FOUND;
    }
}
