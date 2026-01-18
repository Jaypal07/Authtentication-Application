package com.jaypal.authapp.domain.token.entity;

import java.time.Instant;

public record IssuedRefreshToken(
        String token,
        Instant expiresAt
) {}
