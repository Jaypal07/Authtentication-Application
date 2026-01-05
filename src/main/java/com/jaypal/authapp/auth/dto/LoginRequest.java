package com.jaypal.authapp.auth.dto;

import com.jaypal.authapp.audit.model.HasEmail;

public record LoginRequest(
        String email,
        String password
) implements HasEmail {

    @Override
    public String getEmail() {
        return email;
    }
}
