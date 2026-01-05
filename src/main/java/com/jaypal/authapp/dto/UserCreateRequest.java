package com.jaypal.authapp.dto;

import com.jaypal.authapp.audit.model.HasEmail;

public record UserCreateRequest(String email, String password, String name)
        implements HasEmail {

        @Override
        public String getEmail() {
                return email;
        }
}
