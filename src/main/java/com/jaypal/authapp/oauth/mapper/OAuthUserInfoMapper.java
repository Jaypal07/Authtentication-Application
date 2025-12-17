package com.jaypal.authapp.oauth.mapper;

import com.jaypal.authapp.oauth.model.ValidatedOAuthUserInfo;

import java.util.Map;

public interface OAuthUserInfoMapper {

    ValidatedOAuthUserInfo map(Map<String, Object> attributes);
}
