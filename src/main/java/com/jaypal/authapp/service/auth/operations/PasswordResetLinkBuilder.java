package com.jaypal.authapp.service.auth.operations;

import com.jaypal.authapp.config.properties.FrontendProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class PasswordResetLinkBuilder {

    private final FrontendProperties frontendProperties;

    public String buildResetLink(String tokenValue) {
        return frontendProperties.getBaseUrl()
                + "/reset-password?token=" + tokenValue;
    }
}