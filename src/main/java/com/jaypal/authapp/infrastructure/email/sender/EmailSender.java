package com.jaypal.authapp.infrastructure.email.sender;

import com.jaypal.authapp.exception.auth.EmailDeliveryFailedException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

/**
 * Email sender with retry logic.
 * Follows Single Responsibility Principle.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class EmailSender {

    private static final int MAX_RETRY_ATTEMPTS = 3;
    private static final long RETRY_DELAY_MS = 1000L;

    private final JavaMailSender mailSender;

    public void send(
            String from,
            String to,
            String subject,
            String body,
            String emailType
    ) {
        int attempts = 0;
        MailException lastException = null;

        while (attempts < MAX_RETRY_ATTEMPTS) {
            try {
                sendEmail(from, to, subject, body);
                log.info("{} email sent successfully", capitalize(emailType));
                return;

            } catch (MailException ex) {
                lastException = ex;
                attempts++;

                if (attempts < MAX_RETRY_ATTEMPTS) {
                    logRetry(emailType, attempts);
                    sleep(RETRY_DELAY_MS * attempts);
                }
            }
        }

        logFailure(emailType, lastException);
        throw new EmailDeliveryFailedException(
                capitalize(emailType) + " email delivery failed",
                lastException
        );
    }

    private void sendEmail(String from, String to, String subject, String body) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(to);
        message.setSubject(subject);
        message.setText(body);

        mailSender.send(message);
    }

    private void logRetry(String emailType, int attempts) {
        log.warn(
                "{} email failed (attempt {}/{}), retrying...",
                capitalize(emailType),
                attempts,
                MAX_RETRY_ATTEMPTS
        );
    }

    private void logFailure(String emailType, MailException ex) {
        log.error(
                "{} email delivery failed after {} attempts",
                capitalize(emailType),
                MAX_RETRY_ATTEMPTS,
                ex
        );
    }

    private void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new EmailDeliveryFailedException("Email sending interrupted", ie);
        }
    }

    private String capitalize(String value) {
        return value.substring(0, 1).toUpperCase() + value.substring(1);
    }
}