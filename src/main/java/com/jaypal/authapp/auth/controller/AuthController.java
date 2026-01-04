package com.jaypal.authapp.auth.controller;

import com.jaypal.authapp.auth.dto.AuthLoginResult;
import com.jaypal.authapp.auth.dto.LoginRequest;
import com.jaypal.authapp.auth.dto.ResetPasswordRequest;
import com.jaypal.authapp.auth.dto.TokenResponse;
import com.jaypal.authapp.auth.service.AuthService;
import com.jaypal.authapp.auth.web.WebAuthFacade;
import com.jaypal.authapp.dto.ForgotPasswordRequest;
import com.jaypal.authapp.dto.UserCreateRequest;
import com.jaypal.authapp.security.jwt.JwtService;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import com.jaypal.authapp.user.mapper.UserMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final WebAuthFacade webAuthFacade;
    private final AuthService authService;
    private final JwtService jwtService;

    @PostMapping("/register")
    public ResponseEntity<String> register(
            @RequestBody @Valid UserCreateRequest request
    ) {
        authService.register(request);
        return ResponseEntity
                .status(201)
                .body("Registration successful. Please verify your email.");
    }

    @GetMapping("/email-verify")
    public ResponseEntity<String> verifyEmail(
            @RequestParam String token
    ) {
        authService.verifyEmail(token);
        return ResponseEntity.ok("Email verified successfully.");
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<Void> resendVerification(
            @RequestParam String email
    ) {
        authService.resendVerification(email);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(
            @RequestBody LoginRequest request,
            HttpServletResponse response
    ) {

        Authentication authentication =
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                request.email(),
                                request.password()
                        )
                );

        SecurityContextHolder
                .getContext()
                .setAuthentication(authentication);

        AuthPrincipal principal =
                (AuthPrincipal) authentication.getPrincipal();

        AuthLoginResult result =
                webAuthFacade.login(principal, response);

        return ResponseEntity.ok(
                TokenResponse.of(
                        result.accessToken(),
                        jwtService.getAccessTtlSeconds(),
                        UserMapper.toResponse(result.user())
                )
        );
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            HttpServletRequest request,
            HttpServletResponse response
    ) {

        AuthLoginResult result =
                webAuthFacade.refresh(request, response);

        return ResponseEntity.ok(
                TokenResponse.of(
                        result.accessToken(),
                        jwtService.getAccessTtlSeconds(),
                        UserMapper.toResponse(result.user())
                )
        );
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        webAuthFacade.logout(request, response);
        SecurityContextHolder.clearContext();
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<Void> forgotPassword(
            @RequestBody ForgotPasswordRequest request
    ) {
        authService.initiatePasswordReset(request.email());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(
            @RequestBody ResetPasswordRequest request
    ) {
        authService.resetPassword(
                request.token(),
                request.newPassword()
        );
        return ResponseEntity.ok("Password reset successful.");
    }
}
