package com.jaypal.authapp.service.oauth.operations;

import com.jaypal.authapp.domain.user.entity.Provider;
import com.jaypal.authapp.domain.user.entity.User;
import com.jaypal.authapp.domain.user.repository.UserRepository;
import com.jaypal.authapp.domain.user.service.UserProvisioningService;
import com.jaypal.authapp.dto.oauth.OAuthLoginResult;
import com.jaypal.authapp.infrastructure.oauth.model.ValidatedOAuthUserInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuthUserProvisioner {

    private final UserRepository userRepository;
    private final UserProvisioningService userProvisioningService;

    public OAuthLoginResult provisionAndGenerateTokens(
            Provider provider,
            ValidatedOAuthUserInfo userInfo,
            OAuthTokenGenerator tokenGenerator
    ) {
        User user = findOrCreateUser(provider, userInfo);
        validateUserEnabled(user);
        userProvisioningService.provisionNewUser(user);

        return tokenGenerator.generate(user);
    }

    private User findOrCreateUser(Provider provider, ValidatedOAuthUserInfo info) {
        return userRepository
                .findByProviderAndProviderId(provider, info.providerId())
                .orElseGet(() -> createNewOAuthUser(provider, info));
    }

    private User createNewOAuthUser(Provider provider, ValidatedOAuthUserInfo info) {
        try {
            User newUser = User.createOAuth(
                    provider,
                    info.providerId(),
                    info.email(),
                    info.name(),
                    info.image()
            );

            User saved = userRepository.save(newUser);

            log.info("New OAuth user created - provider: {}, userId: {}",
                    provider, saved.getId());

            return saved;

        } catch (DataIntegrityViolationException ex) {
            log.warn("OAuth user creation conflict - provider: {}, providerId: {} - retrying lookup",
                    provider, info.providerId());

            return userRepository
                    .findByProviderAndProviderId(provider, info.providerId())
                    .orElseThrow(() -> new IllegalStateException(
                            "Failed to create or find OAuth user after conflict", ex));
        }
    }

    private void validateUserEnabled(User user) {
        if (!user.isEnabled()) {
            log.warn("OAuth login attempted for disabled user: {}", user.getId());
            throw new IllegalStateException("User account is disabled");
        }
    }
}
