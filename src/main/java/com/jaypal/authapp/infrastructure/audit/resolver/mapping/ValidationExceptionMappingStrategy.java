package com.jaypal.authapp.infrastructure.audit.resolver.mapping;

import com.jaypal.authapp.domain.audit.entity.AuthFailureReason;
import com.jaypal.authapp.infrastructure.audit.resolver.ExceptionMappingStrategy;
import jakarta.validation.ConstraintViolationException;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.MethodArgumentNotValidException;

@Component
public class ValidationExceptionMappingStrategy implements ExceptionMappingStrategy {

    @Override
    public boolean supports(Throwable throwable) {
        return throwable instanceof MethodArgumentNotValidException ||
                throwable instanceof ConstraintViolationException ||
                throwable instanceof IllegalArgumentException;
    }

    @Override
    public AuthFailureReason mapToFailureReason(Throwable throwable) {
        return AuthFailureReason.VALIDATION_FAILED;
    }
}