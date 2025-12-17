package com.jaypal.authapp.auth.controller;

import com.jaypal.authapp.auth.dto.LoginRequest;
import com.jaypal.authapp.auth.dto.RefreshTokenRequest;
import com.jaypal.authapp.auth.dto.TokenResponse;
import com.jaypal.authapp.dto.*;
import com.jaypal.authapp.security.jwt.JwtService;
import com.jaypal.authapp.infrastructure.cookie.CookieService;
import com.jaypal.authapp.token.model.RefreshToken;
import com.jaypal.authapp.token.service.RefreshTokenService;
import com.jaypal.authapp.user.model.User;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final CookieService cookieService;
    private final ModelMapper modelMapper;

    // ---------------- LOGIN ----------------

    @Transactional
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(
            @RequestBody LoginRequest request,
            HttpServletResponse response
    ) {

        Authentication authentication = authenticate(request);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        User user = (User) authentication.getPrincipal();

        RefreshToken refreshToken =
                refreshTokenService.issue(
                        user,
                        jwtService.getRefreshTtlSeconds()
                );

        String accessToken = jwtService.generateAccessToken(user);
        String refreshJwt =
                jwtService.generateRefreshToken(
                        user,
                        refreshToken.getJti()
                );

        cookieService.attachRefreshCookie(
                response,
                refreshJwt,
                (int) jwtService.getRefreshTtlSeconds()
        );
        cookieService.addNoStoreHeader(response);

        return ResponseEntity.ok(
                TokenResponse.of(
                        accessToken,
                        jwtService.getAccessTtlSeconds(),
                        modelMapper.map(user, UserDto.class)
                )
        );
    }

    // ---------------- REFRESH ----------------

    @Transactional
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            @RequestBody(required = false) RefreshTokenRequest body,
            HttpServletRequest request,
            HttpServletResponse response
    ) {

        String refreshJwt = readRefreshToken(body, request)
                .orElseThrow(() ->
                        new BadCredentialsException("Refresh token is missing"));

        if (!jwtService.isRefreshToken(refreshJwt)) {
            throw new BadCredentialsException("Invalid refresh token");
        }

        String jti = jwtService.getJti(refreshJwt);
        UUID userId = jwtService.getUserId(refreshJwt);

        RefreshToken current =
                refreshTokenService.validate(jti, userId);

        RefreshToken next =
                refreshTokenService.rotate(
                        current,
                        jwtService.getRefreshTtlSeconds()
                );

        String accessToken =
                jwtService.generateAccessToken(current.getUser());

        String newRefreshJwt =
                jwtService.generateRefreshToken(
                        current.getUser(),
                        next.getJti()
                );

        cookieService.attachRefreshCookie(
                response,
                newRefreshJwt,
                (int) jwtService.getRefreshTtlSeconds()
        );
        cookieService.addNoStoreHeader(response);

        return ResponseEntity.ok(
                TokenResponse.of(
                        accessToken,
                        jwtService.getAccessTtlSeconds(),
                        modelMapper.map(current.getUser(), UserDto.class)
                )
        );
    }

    // ---------------- LOGOUT ----------------

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            HttpServletRequest request,
            HttpServletResponse response
    ) {

        readRefreshToken(null, request).ifPresent(token -> {
            try {
                if (jwtService.isRefreshToken(token)) {
                    refreshTokenService
                            .revokeIfExists(jwtService.getJti(token));
                }
            } catch (Exception ignored) {}
        });

        cookieService.clearRefreshCookie(response);
        cookieService.addNoStoreHeader(response);
        SecurityContextHolder.clearContext();

        return ResponseEntity.noContent().build();
    }

    // ---------------- HELPERS ----------------

    private Optional<String> readRefreshToken(
            RefreshTokenRequest body,
            HttpServletRequest request
    ) {

        if (request.getCookies() != null) {
            Optional<String> cookieToken = Arrays.stream(request.getCookies())
                    .filter(c ->
                            cookieService.getRefreshTokenCookieName()
                                    .equals(c.getName()))
                    .map(Cookie::getValue)
                    .filter(v -> !v.isBlank())
                    .findFirst();

            if (cookieToken.isPresent()) return cookieToken;
        }

        if (body != null && body.refreshToken() != null
                && !body.refreshToken().isBlank()) {
            return Optional.of(body.refreshToken());
        }

        String headerToken = request.getHeader("X-Refresh-Token");
        if (headerToken != null && !headerToken.isBlank()) {
            return Optional.of(headerToken.trim());
        }

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.toLowerCase().startsWith("bearer ")) {
            return Optional.of(authHeader.substring(7).trim());
        }

        return Optional.empty();
    }

    private Authentication authenticate(LoginRequest request) {
        try {
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.email(),
                            request.password()
                    )
            );
        } catch (Exception ex) {
            throw new BadCredentialsException("Invalid username or password");
        }
    }
}
