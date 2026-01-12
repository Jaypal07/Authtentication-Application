package com.jaypal.authapp.security.config;

import lombok.extern.slf4j.Slf4j;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.method.MethodAuthorizationDeniedHandler;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@Slf4j
@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class MethodSecurityConfig {

    @Bean
    public MethodAuthorizationDeniedHandler methodAuthorizationDeniedHandler() {
        return (MethodInvocation invocation, AuthorizationResult result) -> {
            final String methodName = invocation.getMethod().getName();
            final String className = invocation.getMethod().getDeclaringClass().getSimpleName();

            log.warn("Method authorization denied: {}.{} - Result: {}",
                    className, methodName, result);

            throw new AccessDeniedException(
                    String.format("Access denied to %s.%s", className, methodName)
            );
        };
    }
}

/*
CHANGELOG:
1. Added logging for method-level authorization denials
2. Added method name and class name to error message for debugging
3. Added @Slf4j for consistent logging
4. Made error message more descriptive with method context
*/