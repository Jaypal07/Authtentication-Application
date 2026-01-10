package com.jaypal.authapp.oauth.mapper;

import com.jaypal.authapp.oauth.model.ValidatedOAuthUserInfo;

import java.util.Map;

public class GoogleOAuthUserInfoMapper
        implements OAuthUserInfoMapper {

    @Override
    public ValidatedOAuthUserInfo map(Map<String, Object> attrs) {

        String sub = getRequired(attrs, "sub");
        String name = getRequired(attrs, "name");
        String email = getRequired(attrs, "email");
        String picture = (String) attrs.get("picture");

        return new ValidatedOAuthUserInfo(
                sub,
                email,
                name,
                picture
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
