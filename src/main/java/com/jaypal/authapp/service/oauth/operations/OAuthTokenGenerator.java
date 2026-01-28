package com.jaypal.authapp.service.oauth.operations;

import com.jaypal.authapp.domain.token.entity.IssuedRefreshToken;
import com.jaypal.authapp.domain.token.service.RefreshTokenService;
import com.jaypal.authapp.domain.user.entity.PermissionType;
import com.jaypal.authapp.domain.user.entity.User;
import com.jaypal.authapp.domain.user.service.PermissionService;
import com.jaypal.authapp.dto.oauth.OAuthLoginResult;
import com.jaypal.authapp.infrastructure.security.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Responsibility: Token issuance only.
 * Does not mutate User entity.
 */
@Component
@RequiredArgsConstructor
public class OAuthTokenGenerator {

    private final PermissionService permissionService;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;

    public OAuthLoginResult generate(User user) {

        Set<PermissionType> permissions =
                permissionService.resolvePermissions(user.getId());

        IssuedRefreshToken refreshToken =
                refreshTokenService.issue(user.getId(), jwtService.getRefreshTtlSeconds());

        String accessToken =
                jwtService.generateAccessToken(user, permissions);

        return new OAuthLoginResult(
                user.getId(),
                accessToken,
                refreshToken.token(),
                refreshToken.expiresAt().getEpochSecond()
        );
    }
}
