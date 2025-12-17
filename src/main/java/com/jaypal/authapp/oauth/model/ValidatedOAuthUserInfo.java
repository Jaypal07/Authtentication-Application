package com.jaypal.authapp.oauth.model;

public record ValidatedOAuthUserInfo(
        String providerId,
        String email,
        String name,
        String image
) {}
