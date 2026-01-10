package com.jaypal.authapp.auth.application;

import com.jaypal.authapp.auth.dto.AuthLoginResult;
import com.jaypal.authapp.auth.event.UserRegisteredEvent;
import com.jaypal.authapp.auth.exception.*;
import com.jaypal.authapp.auth.infrastructure.email.EmailService;
import com.jaypal.authapp.config.FrontendProperties;
import com.jaypal.authapp.security.jwt.JwtService;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import com.jaypal.authapp.token.application.IssuedRefreshToken;
import com.jaypal.authapp.token.application.RefreshTokenService;
import com.jaypal.authapp.token.model.RefreshToken;
import com.jaypal.authapp.user.application.PermissionService;
import com.jaypal.authapp.user.application.UserService;
import com.jaypal.authapp.user.dto.UserCreateRequest;
import com.jaypal.authapp.user.model.PasswordResetToken;
import com.jaypal.authapp.user.model.PermissionType;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.repository.PasswordResetTokenRepository;
import com.jaypal.authapp.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    private final PermissionService permissionService;
    private final UserService userService;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final FrontendProperties frontendProperties;
    private final EmailVerificationService emailVerificationService;
    private final ApplicationEventPublisher eventPublisher;

    // ---------- REGISTER ----------

    @Transactional
    public void register(UserCreateRequest request) {
        User user = userService.createAndReturnDomainUser(request);
        eventPublisher.publishEvent(new UserRegisteredEvent(user.getId()));
    }

    // ---------- LOGIN ----------

    @Transactional
    public AuthLoginResult login(AuthPrincipal principal) {

        User user = userRepository.findById(principal.getUserId())
                .orElseThrow(AuthenticatedUserMissingException::new);

        return issueTokens(user);
    }

    // ---------- REFRESH ----------

    @Transactional
    public AuthLoginResult refresh(String rawRefreshToken) {

        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            throw new InvalidRefreshTokenException();
        }

        RefreshToken current =
                refreshTokenService.validate(rawRefreshToken);

        IssuedRefreshToken next =
                refreshTokenService.rotate(
                        current,
                        jwtService.getRefreshTtlSeconds()
                );

        UUID userId = current.getUserId();

        User user = userRepository.findById(userId)
                .orElseThrow(AuthenticatedUserMissingException::new);

        Set<PermissionType> permissions =
                permissionService.resolvePermissions(userId);

        return new AuthLoginResult(
                user,
                jwtService.generateAccessToken(user, permissions),
                next.token(),
                next.expiresAt().getEpochSecond()
        );
    }


    // ---------- LOGOUT ----------

    @Transactional
    public void logout(String rawRefreshToken) {

        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            return;
        }

        refreshTokenService.revoke(rawRefreshToken);
    }

    // ---------- EMAIL ----------

    @Transactional
    public void verifyEmail(String token) {
        emailVerificationService.verifyEmail(token);
    }

    @Transactional
    public void resendVerification(String email) {
        emailVerificationService.resendVerificationToken(email);
    }

    // ---------- PASSWORD RESET ----------

    @Transactional
    public void initiatePasswordReset(String email) {

        userRepository.findByEmail(email).ifPresent(user -> {

            passwordResetTokenRepository
                    .deleteAllByUser_Id(user.getId());

            String tokenValue = UUID.randomUUID().toString();
            PasswordResetToken token = PasswordResetToken.builder()
                    .token(tokenValue)
                    .user(user)
                    .expiresAt(Instant.now().plusSeconds(900))
                    .build();

            passwordResetTokenRepository.save(token);

            String link =
                    frontendProperties.getBaseUrl()
                            + "/reset-password?token=" + tokenValue;

            try {
                emailService.sendPasswordResetEmail(
                        user.getEmail(),
                        link
                );
            } catch (Exception e) {
                log.error("Password reset email failed", e);
            }
        });
    }

    @Transactional
    public void resetPassword(String tokenValue, String rawPassword) {

        if (rawPassword == null || rawPassword.length() < 8) {
            throw new PasswordPolicyViolationException();
        }

        PasswordResetToken token =
                passwordResetTokenRepository
                        .findByToken(tokenValue)
                        .orElseThrow(PasswordResetTokenInvalidException::new);

        if (token.isUsed()
                || token.getExpiresAt().isBefore(Instant.now())) {
            throw new PasswordResetTokenExpiredException();
        }

        User user = token.getUser();
        user.changePassword(passwordEncoder.encode(rawPassword));
        token.setUsed(true);

        userRepository.save(user);
        passwordResetTokenRepository.save(token);
    }

    // ---------- INTERNAL ----------

    private AuthLoginResult issueTokens(User user) {

        Set<PermissionType> permissions =
                permissionService.resolvePermissions(user.getId());

        IssuedRefreshToken refreshToken =
                refreshTokenService.issue(
                        user.getId(),
                        jwtService.getRefreshTtlSeconds()
                );

        return new AuthLoginResult(
                user,
                jwtService.generateAccessToken(user, permissions),
                refreshToken.token(),
                refreshToken.expiresAt().getEpochSecond()
        );
    }
}
