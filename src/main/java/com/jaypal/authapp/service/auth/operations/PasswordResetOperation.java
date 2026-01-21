package com.jaypal.authapp.service.auth.operations;

import com.jaypal.authapp.config.properties.FrontendProperties;
import com.jaypal.authapp.config.properties.PasswordPolicy;
import com.jaypal.authapp.domain.user.entity.PasswordResetToken;
import com.jaypal.authapp.domain.user.entity.User;
import com.jaypal.authapp.domain.user.repository.PasswordResetTokenRepository;
import com.jaypal.authapp.domain.user.repository.UserRepository;
import com.jaypal.authapp.exception.auth.PasswordResetTokenExpiredException;
import com.jaypal.authapp.exception.auth.PasswordResetTokenInvalidException;
import com.jaypal.authapp.infrastructure.audit.context.AuditContextHolder;
import com.jaypal.authapp.infrastructure.email.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class PasswordResetOperation {

    private static final long PASSWORD_RESET_TTL_SECONDS = 900L;

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final FrontendProperties frontendProperties;
    private final PasswordPolicy passwordPolicy;
    private final PasswordResetLinkBuilder linkBuilder;

    public void initiate(String email) {
        userRepository.findByEmail(email).ifPresentOrElse(
                user -> processInitiation(user),
                () -> handleNonExistentEmail()
        );
    }

    public void reset(String tokenValue, String rawPassword) {
        validateTokenValue(tokenValue);
        passwordPolicy.validate(rawPassword);

        PasswordResetToken token = findAndValidateToken(tokenValue);
        User user = token.getUser();

        applyPasswordReset(user, rawPassword);
        markTokenAsUsed(token);

        log.info(
                "Password reset successful. userId={} permVersion={}",
                user.getId(),
                user.getPermissionVersion()
        );
    }

    private void processInitiation(User user) {
        if (!isEligibleForReset(user)) {
            log.warn(
                    "Password reset blocked. userId={}, enabled={}, emailVerified={}",
                    user.getId(),
                    user.isEnabled(),
                    user.isEmailVerified()
            );
            AuditContextHolder.markNoOp();
            return;
        }

        cleanupOldTokens(user.getId());
        PasswordResetToken token = createToken(user);
        sendResetEmail(user.getEmail(), token.getToken());
    }

    private void handleNonExistentEmail() {
        AuditContextHolder.markNoOp();
        log.debug("Password reset requested for non-existent email");
    }

    private boolean isEligibleForReset(User user) {
        return user.isEnabled() && user.isEmailVerified();
    }

    private void cleanupOldTokens(UUID userId) {
        passwordResetTokenRepository.deleteAllByUser_Id(userId);
    }

    private PasswordResetToken createToken(User user) {
        String tokenValue = UUID.randomUUID().toString();

        PasswordResetToken token = PasswordResetToken.builder()
                .token(tokenValue)
                .user(user)
                .expiresAt(Instant.now().plusSeconds(PASSWORD_RESET_TTL_SECONDS))
                .build();

        return passwordResetTokenRepository.save(token);
    }

    private void sendResetEmail(String email, String tokenValue) {
        String resetLink = linkBuilder.buildResetLink(tokenValue);

        try {
            emailService.sendPasswordResetEmail(email, resetLink);
            log.info("Password reset email sent");
        } catch (Exception ex) {
            log.error("Password reset email failed", ex);
        }
    }

    private void validateTokenValue(String tokenValue) {
        if (tokenValue == null || tokenValue.isBlank()) {
            throw new PasswordResetTokenInvalidException();
        }
    }

    private PasswordResetToken findAndValidateToken(String tokenValue) {
        PasswordResetToken token = passwordResetTokenRepository
                .findByToken(tokenValue)
                .orElseThrow(PasswordResetTokenInvalidException::new);

        if (token.isUsed() || token.getExpiresAt().isBefore(Instant.now())) {
            log.warn("Expired or used password reset token");
            passwordResetTokenRepository.delete(token);
            throw new PasswordResetTokenExpiredException();
        }

        return token;
    }

    private void applyPasswordReset(User user, String rawPassword) {
        user.changePassword(passwordEncoder.encode(rawPassword));
        user.bumpPermissionVersion();
        userRepository.save(user);
    }

    private void markTokenAsUsed(PasswordResetToken token) {
        token.setUsed(true);
        passwordResetTokenRepository.save(token);
    }
}
