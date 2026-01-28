package com.jaypal.authapp.service.oauth;

import com.jaypal.authapp.domain.user.entity.Provider;
import com.jaypal.authapp.dto.oauth.OAuthLoginResult;
import com.jaypal.authapp.infrastructure.oauth.model.ValidatedOAuthUserInfo;
import com.jaypal.authapp.service.oauth.operations.OAuthTokenGenerator;
import com.jaypal.authapp.service.oauth.operations.OAuthUserExtractor;
import com.jaypal.authapp.service.oauth.operations.OAuthUserResolver;
import com.jaypal.authapp.service.oauth.operations.OAuthUserValidator;
import com.jaypal.authapp.service.oauth.operations.ProviderParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;

/**
 * Orchestrates OAuth login flow.
 * Responsibility: orchestration only, no persistence logic.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OAuthLoginService {

    private final OAuthUserExtractor extractor;
    private final OAuthUserValidator validator;
    private final OAuthUserResolver userResolver;
    private final OAuthTokenGenerator tokenGenerator;
    private final ProviderParser providerParser;

    @Transactional
    public OAuthLoginResult login(OAuth2AuthenticationToken authentication) {
        Objects.requireNonNull(authentication, "OAuth token cannot be null");

        Provider provider = providerParser.parse(
                authentication.getAuthorizedClientRegistrationId()
        );

        ValidatedOAuthUserInfo userInfo = extractor.extract(authentication, provider);
        validator.validate(userInfo, provider);

        var user = userResolver.resolveOrCreate(provider, userInfo);

        return tokenGenerator.generate(user);
    }
}
