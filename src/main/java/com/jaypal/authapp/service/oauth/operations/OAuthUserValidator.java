package com.jaypal.authapp.service.oauth.operations;

import com.jaypal.authapp.domain.user.entity.Provider;
import com.jaypal.authapp.infrastructure.oauth.model.ValidatedOAuthUserInfo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class OAuthUserValidator {

    public void validate(ValidatedOAuthUserInfo info, Provider provider) {
        validateNotNull(info);
        validateProviderId(info.providerId());
        validateEmail(info.email(), provider);
        validateName(info.name());

        log.debug("OAuth user info validated - provider: {}, email: {}",
                provider, maskEmail(info.email()));
    }

    private void validateNotNull(ValidatedOAuthUserInfo info) {
        if (info == null) {
            throw new IllegalStateException("OAuth user info is null");
        }
    }

    private void validateProviderId(String providerId) {
        if (providerId == null || providerId.isBlank()) {
            throw new IllegalStateException("OAuth provider ID is missing");
        }
    }

    private void validateEmail(String email, Provider provider) {
        if (email == null || email.isBlank()) {
            throw new IllegalStateException("OAuth email is missing");
        }

        if (!email.contains("@")) {
            log.warn("Invalid email format from OAuth provider: {}", provider);
            throw new IllegalStateException("Invalid email format");
        }
    }

    private void validateName(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalStateException("OAuth name is missing");
        }
    }

    private String maskEmail(String email) {
        if (email == null || email.length() <= 3) {
            return "***";
        }

        int atIndex = email.indexOf('@');
        if (atIndex <= 0) {
            return email.substring(0, 2) + "***";
        }

        return email.substring(0, Math.min(2, atIndex)) + "***" + email.substring(atIndex);
    }
}