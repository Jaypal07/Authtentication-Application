package com.jaypal.authapp.infrastructure.audit.resolver.mapping;

import com.jaypal.authapp.domain.audit.entity.AuthFailureReason;
import com.jaypal.authapp.infrastructure.audit.resolver.ExceptionMappingStrategy;
import com.jaypal.authapp.infrastructure.oauth.handler.OAuthAuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class OAuthExceptionMappingStrategy implements ExceptionMappingStrategy {

    @Override
    public boolean supports(Throwable throwable) {
        return throwable instanceof OAuthAuthenticationException;
    }

    @Override
    public AuthFailureReason mapToFailureReason(Throwable throwable) {
        return AuthFailureReason.OAUTH_PROVIDER_ERROR;
    }
}