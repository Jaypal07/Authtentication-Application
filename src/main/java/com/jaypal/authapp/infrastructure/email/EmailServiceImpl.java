package com.jaypal.authapp.infrastructure.email;

import com.jaypal.authapp.domain.user.entity.User;
import com.jaypal.authapp.domain.user.repository.UserRepository;
import com.jaypal.authapp.exception.auth.EmailAlreadyVerifiedException;
import com.jaypal.authapp.exception.auth.EmailDeliveryFailedException;
import com.jaypal.authapp.exception.auth.SilentEmailVerificationResendException;
import com.jaypal.authapp.infrastructure.email.sender.EmailSender;
import com.jaypal.authapp.infrastructure.email.template.EmailTemplateBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Refactored EmailService following SOLID principles.
 * Delegates email sending and template building to specialized components.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    private final EmailSender emailSender;
    private final EmailTemplateBuilder templateBuilder;
    private final UserRepository userRepository;

    @Value("${spring.mail.username:noreply@example.com}")
    private String fromAddress;

    @Override
    public void sendPasswordResetEmail(String to, String resetLink) {
        if (to == null || to.isBlank() || resetLink == null || resetLink.isBlank()) {
            return;
        }

        userRepository.findByEmail(to).ifPresent(user -> {
            if (!user.isEmailVerified()) {
                log.debug("Password reset requested for unverified email");
                return;
            }

            String body = templateBuilder.buildPasswordResetBody(resetLink);
            emailSender.send(fromAddress, to, "Reset Your Password", body, "password reset");
        });
    }

    @Override
    public void sendVerificationEmail(String to, String verifyLink) {
        if (to == null || to.isBlank() || verifyLink == null || verifyLink.isBlank()) {
            return;
        }

        User user = userRepository.findByEmail(to)
                .orElseThrow(() ->
                        new SilentEmailVerificationResendException(
                                "Resend verification requested for non-existent email"
                        )
                );

        if (user.isEmailVerified()) {
            throw new EmailAlreadyVerifiedException("Email already verified");
        }

        String body = templateBuilder.buildVerificationBody(verifyLink);
        emailSender.send(fromAddress, to, "Verify Your Email Address", body, "verification");
    }
}
