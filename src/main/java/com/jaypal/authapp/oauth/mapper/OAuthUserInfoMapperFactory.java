package com.jaypal.authapp.oauth.mapper;

import com.jaypal.authapp.user.model.Provider;

public final class OAuthUserInfoMapperFactory {

    private OAuthUserInfoMapperFactory() {}

    public static OAuthUserInfoMapper get(Provider provider) {
        return switch (provider) {
            case GOOGLE -> new GoogleOAuthUserInfoMapper();
            case GITHUB -> new GithubOAuthUserInfoMapper();
            default ->
                    throw new IllegalStateException(
                            "Unsupported OAuth provider: " + provider
                    );
        };
    }
}
