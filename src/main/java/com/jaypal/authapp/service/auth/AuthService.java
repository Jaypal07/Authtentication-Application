package com.jaypal.authapp.service.auth;

import com.jaypal.authapp.dto.auth.AuthLoginResult;
import com.jaypal.authapp.dto.user.UserCreateRequest;
import com.jaypal.authapp.event.UserRegisteredEvent;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import com.jaypal.authapp.service.auth.operations.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.UUID;

/**
 * Refactored AuthService following SOLID principles.
 * Delegates operations to specialized components.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final ApplicationEventPublisher eventPublisher;

    // Operation handlers
    private final RegistrationOperation registrationOperation;
    private final LoginOperation loginOperation;
    private final TokenRefreshOperation tokenRefreshOperation;
    private final LogoutOperation logoutOperation;
    private final EmailVerificationOperation emailVerificationOperation;
    private final PasswordResetOperation passwordResetOperation;

    @Transactional
    public void register(UserCreateRequest request) {
        Objects.requireNonNull(request, "UserCreateRequest must not be null");

        log.debug("Registration requested. email={}", request.email());

        UUID userId = registrationOperation.execute(request);

        log.info("User registered successfully. userId={}", userId);

        eventPublisher.publishEvent(new UserRegisteredEvent(userId));
        log.debug("UserRegisteredEvent published. userId={}", userId);
    }

    @Transactional
    public AuthLoginResult login(AuthPrincipal principal) {
        Objects.requireNonNull(principal, "Principal cannot be null");
        Objects.requireNonNull(principal.getUserId(), "User ID cannot be null");

        log.debug("Login invoked. userId={}", principal.getUserId());

        AuthLoginResult result = loginOperation.execute(principal);

        log.info("User logged in successfully. userId={}", principal.getUserId());

        return result;
    }

    @Transactional
    public AuthLoginResult refresh(String rawRefreshToken) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            log.warn("Refresh attempted with blank token");
            throw new IllegalArgumentException("Refresh token is invalid");
        }

        return tokenRefreshOperation.execute(rawRefreshToken);
    }

    @Transactional
    public void logout(String rawRefreshToken) {
        logoutOperation.executeSingleSession(rawRefreshToken);
    }

    @Transactional
    public void logoutAllSessions(UUID userId) {
        Objects.requireNonNull(userId, "User ID cannot be null");
        logoutOperation.executeAllSessions(userId);
    }

    @Transactional
    public void verifyEmail(String token) {
        emailVerificationOperation.verify(token);
    }

    public void resendVerification(String email) {
        emailVerificationOperation.resend(email);
    }

    @Transactional
    public void initiatePasswordReset(String email) {
        passwordResetOperation.initiate(email);
    }

    @Transactional
    public void resetPassword(String tokenValue, String rawPassword) {
        passwordResetOperation.reset(tokenValue, rawPassword);
    }

    @Transactional(readOnly = true)
    public String resolveUserId(String rawRefreshToken) {
        return logoutOperation.resolveUserIdForAudit(rawRefreshToken);
    }
}
