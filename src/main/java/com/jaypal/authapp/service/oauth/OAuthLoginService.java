package com.jaypal.authapp.service.oauth;

import com.jaypal.authapp.domain.user.entity.Provider;
import com.jaypal.authapp.dto.oauth.OAuthLoginResult;
import com.jaypal.authapp.infrastructure.oauth.model.ValidatedOAuthUserInfo;
import com.jaypal.authapp.service.oauth.operations.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;

/**
 * Refactored OAuthLoginService following SOLID principles.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OAuthLoginService {

    private final OAuthUserExtractor userExtractor;
    private final OAuthUserValidator userValidator;
    private final OAuthUserProvisioner userProvisioner;
    private final OAuthTokenGenerator tokenGenerator;
    private final ProviderParser providerParser;

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public OAuthLoginResult login(OAuth2AuthenticationToken authentication) {
        Objects.requireNonNull(authentication, "OAuth authentication token cannot be null");

        Provider provider = providerParser.parse(
                authentication.getAuthorizedClientRegistrationId()
        );

        log.info("OAuth login initiated - provider: {}", provider);

        ValidatedOAuthUserInfo userInfo = userExtractor.extract(authentication, provider);
        userValidator.validate(userInfo, provider);

        OAuthLoginResult result = userProvisioner.provisionAndGenerateTokens(
                provider,
                userInfo,
                tokenGenerator
        );

        log.info("OAuth login successful - provider: {}, userId: {}", provider, result.userId());

        return result;
    }
}
