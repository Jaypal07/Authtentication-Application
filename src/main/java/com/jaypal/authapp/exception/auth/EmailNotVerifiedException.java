package com.jaypal.authapp.exception.auth;

import org.springframework.security.core.AuthenticationException;

public class EmailNotVerifiedException extends AuthenticationException {
    public EmailNotVerifiedException() {
        super("Email not verified, please verify your email before login!");
    }
}