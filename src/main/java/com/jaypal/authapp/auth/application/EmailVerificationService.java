package com.jaypal.authapp.auth.application;

import com.jaypal.authapp.auth.exception.EmailAlreadyVerifiedException;
import com.jaypal.authapp.auth.exception.EmailNotRegisteredException;
import com.jaypal.authapp.auth.exception.VerificationTokenExpiredException;
import com.jaypal.authapp.auth.exception.VerificationTokenInvalidException;
import com.jaypal.authapp.auth.infrastructure.email.EmailService;
import com.jaypal.authapp.config.FrontendProperties;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.model.VerificationToken;
import com.jaypal.authapp.user.repository.EmailVerificationTokenRepository;
import com.jaypal.authapp.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private final EmailVerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final FrontendProperties frontendProperties;

    @Transactional
    public void createVerificationToken(UUID userId) {
        Objects.requireNonNull(userId, "User ID cannot be null");

        final User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.error("User not found during verification token creation: {}", userId);
                    return new IllegalStateException("User not found for verification: " + userId);
                });

        if (user.isEmailVerified()) {
            log.debug("Verification token creation skipped - already verified: {}", userId);
            return;
        }

        final VerificationToken token = tokenRepository.findByUserId(userId)
                .orElseGet(() -> new VerificationToken(user));

        token.regenerate();
        tokenRepository.save(token);

        final String verifyLink = String.format(
                "%s/email-verify?token=%s",
                frontendProperties.getBaseUrl(),
                token.getToken()
        );

        try {
            emailService.sendVerificationEmail(user.getEmail(), verifyLink);
            log.info("Verification email sent - User ID: {}", userId);
        } catch (Exception ex) {
            log.error("Verification email failed - User ID: {}", userId, ex);
            throw new IllegalStateException("Failed to send verification email", ex);
        }
    }

    @Transactional
    public void resendVerificationToken(String email) {
        Objects.requireNonNull(email, "Email cannot be null");

        if (email.isBlank()) {
            throw new EmailNotRegisteredException();
        }

        final User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.debug("Verification resend requested for non-existent email");
                    return new EmailNotRegisteredException();
                });

        if (user.isEmailVerified()) {
            log.debug("Verification resend requested for already-verified user: {}", user.getId());
            return;
        }

        createVerificationToken(user.getId());
    }

    @Transactional
    public void verifyEmail(String tokenValue) {
        Objects.requireNonNull(tokenValue, "Token cannot be null");

        if (tokenValue.isBlank()) {
            throw new VerificationTokenInvalidException();
        }

        final VerificationToken token = tokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> {
                    log.warn("Email verification attempted with invalid token");
                    return new VerificationTokenInvalidException();
                });

        if (token.isExpired()) {
            log.warn("Email verification attempted with expired token - User ID: {}",
                    token.getUser().getId());
            tokenRepository.delete(token);
            throw new VerificationTokenExpiredException();
        }

        final UUID userId = token.getUser().getId();
        final User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.error("User not found during email verification: {}", userId);
                    return new IllegalStateException("User missing during verification: " + userId);
                });

        if (user.isEmailVerified()) {
            log.debug("Email verification for already-verified user: {}", userId);
            tokenRepository.delete(token);
            return;
        }

        user.enable();
        userRepository.save(user);
        tokenRepository.delete(token);

        log.info("Email verified successfully - User ID: {}", userId);
    }
}

/*
CHANGELOG:
1. Added null checks for all method parameters
2. Added blank check for email in resendVerificationToken
3. Added blank check for tokenValue in verifyEmail
4. Added check to skip token creation if email already verified
5. Added check to handle already-verified users during verification
6. Added try-catch for email sending with descriptive error
7. Changed string concatenation to String.format for URL construction
8. Added comprehensive logging for all operations
9. Made all logging statements include user ID for audit trail
10. Changed isEnabled() check to isEmailVerified() for clarity
11. Added final modifiers to all local variables
*/