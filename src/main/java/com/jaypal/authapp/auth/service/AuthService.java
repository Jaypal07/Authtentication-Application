package com.jaypal.authapp.auth.service;

import com.jaypal.authapp.auth.dto.AuthLoginResult;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import com.jaypal.authapp.security.jwt.JwtService;
import com.jaypal.authapp.token.model.RefreshToken;
import com.jaypal.authapp.token.service.RefreshTokenService;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;

    @Transactional
    public AuthLoginResult login(AuthPrincipal principal) {

        User user = userRepository.findById(principal.getUserId())
                .orElseThrow(() ->
                        new IllegalStateException(
                                "Authenticated user not found"
                        ));

        RefreshToken refreshToken =
                refreshTokenService.issue(
                        user,
                        jwtService.getRefreshTtlSeconds()
                );

        return new AuthLoginResult(
                user,
                jwtService.generateAccessToken(user),
                jwtService.generateRefreshToken(
                        user,
                        refreshToken.getJti()
                ),
                jwtService.getRefreshTtlSeconds()
        );
    }
}
