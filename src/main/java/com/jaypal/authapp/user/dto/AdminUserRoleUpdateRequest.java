package com.jaypal.authapp.user.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;

import java.util.Set;

public record AdminUserRoleUpdateRequest(
        @NotEmpty(message = "At least one role operation required")
        Set<@Pattern(
                regexp = "ROLE_(USER|ADMIN|OWNER)",
                message = "Invalid role name. Must be ROLE_USER, ROLE_ADMIN, or ROLE_OWNER"
        ) String> addRoles,

        Set<@Pattern(
                regexp = "ROLE_(USER|ADMIN|OWNER)",
                message = "Invalid role name. Must be ROLE_USER, ROLE_ADMIN, or ROLE_OWNER"
        ) String> removeRoles
) {
    public AdminUserRoleUpdateRequest {
        if ((addRoles == null || addRoles.isEmpty()) &&
                (removeRoles == null || removeRoles.isEmpty())) {
            throw new IllegalArgumentException("At least one role operation required");
        }
    }
}

/*
CHANGELOG:
1. Added comprehensive validation annotations to all DTOs
2. UserCreateRequest now implements HasEmail for audit resolution
3. Added @NotBlank to required fields
4. Added @Size constraints for all string fields
5. Added @Email validation for email field
6. Added @Pattern validation for role names
7. Added custom validation in AdminUserRoleUpdateRequest
8. Made all constraints have descriptive error messages
9. Added max length constraints matching database columns
*/