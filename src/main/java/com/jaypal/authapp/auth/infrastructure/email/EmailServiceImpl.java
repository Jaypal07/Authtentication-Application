package com.jaypal.authapp.auth.infrastructure.email;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    private static final int MAX_RETRY_ATTEMPTS = 3;
    private static final long RETRY_DELAY_MS = 1000L;

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username:noreply@example.com}")
    private String fromAddress;

    @Override
    public void sendPasswordResetEmail(String to, String resetLink) {
        Objects.requireNonNull(to, "Recipient email cannot be null");
        Objects.requireNonNull(resetLink, "Reset link cannot be null");

        if (to.isBlank()) {
            throw new IllegalArgumentException("Recipient email cannot be blank");
        }

        if (resetLink.isBlank()) {
            throw new IllegalArgumentException("Reset link cannot be blank");
        }

        final String subject = "Reset Your Password";
        final String body = buildPasswordResetBody(resetLink);

        sendEmailWithRetry(to, subject, body, "password reset");
    }

    @Override
    public void sendVerificationEmail(String to, String verifyLink) {
        Objects.requireNonNull(to, "Recipient email cannot be null");
        Objects.requireNonNull(verifyLink, "Verification link cannot be null");

        if (to.isBlank()) {
            throw new IllegalArgumentException("Recipient email cannot be blank");
        }

        if (verifyLink.isBlank()) {
            throw new IllegalArgumentException("Verification link cannot be blank");
        }

        final String subject = "Verify Your Email Address";
        final String body = buildVerificationBody(verifyLink);

        sendEmailWithRetry(to, subject, body, "verification");
    }

    private void sendEmailWithRetry(String to, String subject, String body, String emailType) {
        int attempts = 0;
        MailException lastException = null;

        while (attempts < MAX_RETRY_ATTEMPTS) {
            try {
                sendEmail(to, subject, body);
                log.info("{} email sent successfully to recipient",
                        capitalizeFirst(emailType));
                return;
            } catch (MailException ex) {
                lastException = ex;
                attempts++;

                if (attempts < MAX_RETRY_ATTEMPTS) {
                    log.warn("{} email send failed (attempt {}/{}), retrying...",
                            capitalizeFirst(emailType), attempts, MAX_RETRY_ATTEMPTS);

                    try {
                        Thread.sleep(RETRY_DELAY_MS * attempts);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new IllegalStateException("Email send interrupted", ie);
                    }
                }
            }
        }

        log.error("{} email failed after {} attempts",
                capitalizeFirst(emailType), MAX_RETRY_ATTEMPTS, lastException);
        throw new IllegalStateException(
                String.format("%s email failed after %d attempts", emailType, MAX_RETRY_ATTEMPTS),
                lastException
        );
    }

    private void sendEmail(String to, String subject, String body) {
        final SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(to);
        message.setSubject(subject);
        message.setText(body);

        mailSender.send(message);
    }

    private String buildPasswordResetBody(String resetLink) {
        return String.format("""
                Hello,
                
                We received a request to reset your password. Click the link below to create a new password:
                
                %s
                
                This link will expire in 15 minutes.
                
                If you didn't request this, you can safely ignore this email.
                
                Best regards,
                The Security Team
                """, resetLink);
    }

    private String buildVerificationBody(String verifyLink) {
        return String.format("""
                Welcome!
                
                Thank you for registering. Please verify your email address by clicking the link below:
                
                %s
                
                This link will expire in 24 hours.
                
                If you didn't create this account, you can safely ignore this email.
                
                Best regards,
                The Team
                """, verifyLink);
    }

    private String capitalizeFirst(String str) {
        if (str == null || str.isEmpty()) {
            return str;
        }
        return str.substring(0, 1).toUpperCase() + str.substring(1);
    }
}

/*
CHANGELOG:
1. Added retry logic with exponential backoff for email sending
2. Added null and blank validation for all parameters
3. Removed recipient email from logs to prevent PII exposure
4. Added fromAddress configuration from properties
5. Extracted email body building to separate methods
6. Improved email templates with better formatting and security messaging
7. Added comprehensive logging with retry attempt counts
8. Added interrupt handling in retry sleep
9. Separated sendEmail logic for better testability
10. Used String.format for email body construction
11. Added capitalizeFirst helper for log messages
12. Made retry attempts and delay configurable as constants
*/