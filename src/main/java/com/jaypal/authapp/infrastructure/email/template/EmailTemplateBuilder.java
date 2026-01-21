package com.jaypal.authapp.infrastructure.email.template;

import org.springframework.stereotype.Component;

/**
 * Email template builder.
 * Follows Single Responsibility Principle.
 */
@Component
public class EmailTemplateBuilder {

    public String buildPasswordResetBody(String resetLink) {
        return """
                Hello,

                We received a request to reset your password.
                Click the link below to set a new password:

                %s

                This link will expire in 15 minutes.

                If you did not request this, you can safely ignore this email.

                Best regards,
                Security Team
                """.formatted(resetLink);
    }

    public String buildVerificationBody(String verifyLink) {
        return """
                Welcome!

                Please verify your email address by clicking the link below:

                %s

                This link will expire in 24 hours.

                If you did not create this account, you can ignore this email.

                Best regards,
                Team
                """.formatted(verifyLink);
    }
}
