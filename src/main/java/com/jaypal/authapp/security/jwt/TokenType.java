package com.jaypal.authapp.security.jwt;

public enum TokenType {
    ACCESS,
    REFRESH;

    public static TokenType from(String value) {
        return TokenType.valueOf(value.toUpperCase());
    }
}
