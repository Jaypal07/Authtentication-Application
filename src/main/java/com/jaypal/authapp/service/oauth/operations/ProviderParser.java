package com.jaypal.authapp.service.oauth.operations;

import com.jaypal.authapp.domain.user.entity.Provider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class ProviderParser {

    public Provider parse(String registrationId) {
        if (registrationId == null || registrationId.isBlank()) {
            throw new IllegalArgumentException("OAuth registration ID is missing");
        }

        try {
            return Provider.valueOf(registrationId.toUpperCase());
        } catch (IllegalArgumentException ex) {
            log.error("Unsupported OAuth provider: {}", registrationId);
            throw new IllegalStateException("Unsupported OAuth provider: " + registrationId, ex);
        }
    }
}