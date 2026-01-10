package com.jaypal.authapp.token.application;

import java.time.Instant;

public record IssuedRefreshToken(
        String token,
        Instant expiresAt
) {}
