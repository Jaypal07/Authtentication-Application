package com.jaypal.authapp.auth.dto;

public record LoginRequest(
        String email,
        String password
){}
