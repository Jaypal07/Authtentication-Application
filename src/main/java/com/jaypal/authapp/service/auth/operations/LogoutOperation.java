package com.jaypal.authapp.service.auth.operations;

import com.jaypal.authapp.domain.token.exception.RefreshTokenExpiredException;
import com.jaypal.authapp.domain.token.exception.RefreshTokenNotFoundException;
import com.jaypal.authapp.domain.token.exception.RefreshTokenRevokedException;
import com.jaypal.authapp.domain.token.service.RefreshTokenService;
import com.jaypal.authapp.domain.user.entity.User;
import com.jaypal.authapp.domain.user.repository.UserRepository;
import com.jaypal.authapp.exception.auth.AuthenticatedUserMissingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class LogoutOperation {

    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;

    public void executeSingleSession(String rawRefreshToken) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            log.debug("Logout called without refresh token");
            return;
        }

        try {
            refreshTokenService.revoke(rawRefreshToken);
            log.debug("Refresh token revoked");
        } catch (RefreshTokenNotFoundException ex) {
            log.debug("Refresh token already revoked or expired");
        } catch (Exception ex) {
            log.warn(
                    "Unexpected error during refresh token revoke | type={} message={}",
                    ex.getClass().getSimpleName(),
                    ex.getMessage()
            );
        }
    }

    public void executeAllSessions(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.error("Logout-all failed. User not found. userId={}", userId);
                    return new AuthenticatedUserMissingException();
                });

        user.bumpPermissionVersion();
        refreshTokenService.revokeAllForUser(userId);
        userRepository.save(user);

        log.info(
                "All sessions revoked. userId={} permVersion={}",
                userId,
                user.getPermissionVersion()
        );
    }

    public String resolveUserIdForAudit(String rawRefreshToken) {
        try {
            return refreshTokenService
                    .validate(rawRefreshToken)
                    .getUserId()
                    .toString();
        } catch (RefreshTokenNotFoundException |
                 RefreshTokenExpiredException |
                 RefreshTokenRevokedException ex) {

            log.debug(
                    "Unable to resolve userId from refresh token for audit | reason={}",
                    ex.getClass().getSimpleName()
            );
            return null;
        }
    }
}
