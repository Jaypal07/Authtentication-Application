package com.jaypal.authapp.dto;

public record UserUpdateRequest(
        String name,
        String image,
        String password
) {}
