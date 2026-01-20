package com.jaypal.authapp.dto.oauth;

import java.util.UUID;

public record OAuthLoginResult(
        UUID userId,
        String accessToken,
        String refreshToken,
        long refreshTtlSeconds
) {}
