package com.jaypal.authapp.service.auth.operations;

import com.jaypal.authapp.domain.token.entity.IssuedRefreshToken;
import com.jaypal.authapp.domain.token.entity.RefreshToken;
import com.jaypal.authapp.domain.token.service.RefreshTokenService;
import com.jaypal.authapp.domain.user.entity.PermissionType;
import com.jaypal.authapp.domain.user.entity.User;
import com.jaypal.authapp.domain.user.repository.UserRepository;
import com.jaypal.authapp.domain.user.service.PermissionService;
import com.jaypal.authapp.dto.auth.AuthLoginResult;
import com.jaypal.authapp.exception.auth.AuthenticatedUserMissingException;
import com.jaypal.authapp.infrastructure.security.jwt.JwtService;
import com.jaypal.authapp.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class TokenRefreshOperation {

    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;
    private final PermissionService permissionService;
    private final JwtService jwtService;

    public AuthLoginResult execute(String rawRefreshToken) {
        RefreshToken current = refreshTokenService.validate(rawRefreshToken);

        IssuedRefreshToken next = refreshTokenService.rotate(
                current.getId(),
                jwtService.getRefreshTtlSeconds()
        );

        UUID userId = current.getUserId();
        User user = findAndValidateUser(userId);
        Set<PermissionType> permissions = permissionService.resolvePermissions(userId);

        log.debug(
                "Refresh successful. userId={} permissions={} permVersion={}",
                userId,
                permissions.size(),
                user.getPermissionVersion()
        );

        return new AuthLoginResult(
                UserMapper.toResponse(user, permissions),
                jwtService.generateAccessToken(user, permissions),
                next.token(),
                next.expiresAt().getEpochSecond()
        );
    }

    private User findAndValidateUser(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.error("Refresh failed. User not found. userId={}", userId);
                    return new AuthenticatedUserMissingException();
                });

        if (!user.isEnabled()) {
            log.warn("Refresh blocked for disabled user. userId={}", userId);
            throw new AuthenticatedUserMissingException();
        }

        return user;
    }
}