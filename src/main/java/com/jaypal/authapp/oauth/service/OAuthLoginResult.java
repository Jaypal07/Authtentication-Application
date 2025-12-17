package com.jaypal.authapp.oauth.service;

public record OAuthLoginResult(
        String accessToken,
        String refreshToken,
        long refreshTtlSeconds
) {}
