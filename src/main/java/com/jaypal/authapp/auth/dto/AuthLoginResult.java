package com.jaypal.authapp.auth.dto;

import com.jaypal.authapp.user.model.User;

public record AuthLoginResult(
        User user,
        String accessToken,
        String refreshToken,
        long refreshExpiresAtEpochSeconds
) {}
