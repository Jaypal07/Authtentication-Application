package com.jaypal.authapp.auth.dto;

public record ResetPasswordRequest(
        String token,
        String newPassword
) {}
