package com.jaypal.authapp.service.oauth.operations;

import com.jaypal.authapp.domain.user.entity.Provider;
import com.jaypal.authapp.infrastructure.oauth.model.ValidatedOAuthUserInfo;
import com.jaypal.authapp.mapper.OAuthUserInfoMapperFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class OAuthUserExtractor {

    public ValidatedOAuthUserInfo extract(
            OAuth2AuthenticationToken authentication,
            Provider provider
    ) {
        try {
            return OAuthUserInfoMapperFactory.get(provider)
                    .map(authentication.getPrincipal().getAttributes());
        } catch (Exception ex) {
            log.error("Failed to extract OAuth user info - provider: {}", provider, ex);
            throw new IllegalStateException(
                    "Failed to extract user information from OAuth provider",
                    ex
            );
        }
    }
}