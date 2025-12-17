package com.jaypal.authapp.oauth.mapper;

import com.jaypal.authapp.oauth.model.ValidatedOAuthUserInfo;

import java.util.Map;

public class GithubOAuthUserInfoMapper
        implements OAuthUserInfoMapper {

    @Override
    public ValidatedOAuthUserInfo map(Map<String, Object> attrs) {

        String id = getRequired(attrs, "id");
        String login = getRequired(attrs, "login");

        String email = (String) attrs.get("email");
        String avatar = (String) attrs.get("avatar_url");

        return new ValidatedOAuthUserInfo(
                id,
                email,
                login,
                avatar
        );
    }

    private String getRequired(Map<String, Object> attrs, String key) {
        Object value = attrs.get(key);
        if (value == null || value.toString().isBlank()) {
            throw new IllegalArgumentException(
                    "Missing required OAuth attribute: " + key
            );
        }
        return value.toString();
    }
}
