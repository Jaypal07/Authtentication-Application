package com.jaypal.authapp.user.dto;

import jakarta.validation.constraints.Size;

public record AdminUserUpdateRequest(
        @Size(min = 1, max = 255, message = "Name must be between 1 and 255 characters")
        String name,

        @Size(max = 512, message = "Image URL must not exceed 512 characters")
        String image,

        Boolean enabled
) {}