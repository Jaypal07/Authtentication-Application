package com.jaypal.authapp.dto.auth;

import com.jaypal.authapp.domain.audit.entity.HasEmail;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record PasswordResetRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        @Pattern(
                regexp = "^[\\x00-\\x7F]+$",
                message = "Email must contain only ASCII characters"
        )
        @Pattern(
                regexp = "^(?!.*\\$).*$",
                message = "Invalid email format"
        )
        @Size(max = 255, message = "Email must not exceed 255 characters")
        String email
) implements HasEmail {
    @Override
    public String getEmail() {
        return email;
    }
}