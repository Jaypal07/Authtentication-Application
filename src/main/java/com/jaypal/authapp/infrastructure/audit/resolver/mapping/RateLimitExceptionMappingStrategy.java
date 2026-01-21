package com.jaypal.authapp.infrastructure.audit.resolver.mapping;

import com.jaypal.authapp.domain.audit.entity.AuthFailureReason;
import com.jaypal.authapp.infrastructure.audit.resolver.ExceptionMappingStrategy;
import com.jaypal.authapp.infrastructure.ratelimit.RateLimitExceededException;
import org.springframework.stereotype.Component;

@Component
public class RateLimitExceptionMappingStrategy implements ExceptionMappingStrategy {

    @Override
    public boolean supports(Throwable throwable) {
        return throwable instanceof RateLimitExceededException;
    }

    @Override
    public AuthFailureReason mapToFailureReason(Throwable throwable) {
        return AuthFailureReason.RATE_LIMIT_EXCEEDED;
    }
}