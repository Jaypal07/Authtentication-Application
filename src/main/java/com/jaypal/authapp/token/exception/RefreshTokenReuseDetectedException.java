package com.jaypal.authapp.token.exception;

public class RefreshTokenReuseDetectedException extends RefreshTokenException {
    public RefreshTokenReuseDetectedException() {
        super("Reuse refresh token");
    }
}
