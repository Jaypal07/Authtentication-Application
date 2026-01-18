package com.jaypal.authapp.auth.exception;

public class PasswordResetTokenUsedException extends RuntimeException {
    public PasswordResetTokenUsedException(String message) {
        super(message);
    }
}
