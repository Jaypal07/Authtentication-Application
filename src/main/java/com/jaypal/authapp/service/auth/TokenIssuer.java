package com.jaypal.authapp.service.auth;

import com.jaypal.authapp.domain.token.entity.IssuedRefreshToken;
import com.jaypal.authapp.domain.token.service.RefreshTokenService;
import com.jaypal.authapp.domain.user.entity.PermissionType;
import com.jaypal.authapp.domain.user.entity.User;
import com.jaypal.authapp.domain.user.service.PermissionService;
import com.jaypal.authapp.dto.auth.AuthLoginResult;
import com.jaypal.authapp.infrastructure.security.jwt.JwtService;
import com.jaypal.authapp.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class TokenIssuer {

    private final PermissionService permissionService;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;

    public AuthLoginResult issueTokens(User user) {
        Set<PermissionType> permissions = permissionService.resolvePermissions(user.getId());

        IssuedRefreshToken refreshToken = refreshTokenService.issue(
                user.getId(),
                jwtService.getRefreshTtlSeconds()
        );

        log.debug(
                "Issuing tokens. userId={} permissions={} permVersion={}",
                user.getId(),
                permissions.size(),
                user.getPermissionVersion()
        );

        return new AuthLoginResult(
                UserMapper.toResponse(user, permissions),
                jwtService.generateAccessToken(user, permissions),
                refreshToken.token(),
                refreshToken.expiresAt().getEpochSecond()
        );
    }
}