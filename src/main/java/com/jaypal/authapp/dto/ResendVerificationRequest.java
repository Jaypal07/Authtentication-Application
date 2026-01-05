package com.jaypal.authapp.dto;

import com.jaypal.authapp.audit.model.HasEmail;

public record ResendVerificationRequest(String email)
        implements HasEmail {

    @Override
    public String getEmail() {
        return email;
    }
}
