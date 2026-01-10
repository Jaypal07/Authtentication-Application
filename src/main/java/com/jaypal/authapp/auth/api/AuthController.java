package com.jaypal.authapp.auth.api;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.domain.AuthAuditEvent;
import com.jaypal.authapp.audit.domain.AuditSubjectType;
import com.jaypal.authapp.auth.dto.*;
import com.jaypal.authapp.auth.application.AuthService;
import com.jaypal.authapp.auth.facade.WebAuthFacade;
import com.jaypal.authapp.user.dto.UserCreateRequest;
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

    // ---------- REGISTRATION ----------

    @AuthAudit(
            event = AuthAuditEvent.REGISTER,
            subject = AuditSubjectType.EMAIL
    )
    @PostMapping("/register")
    public ResponseEntity<String> register(
            @RequestBody @Valid UserCreateRequest request
    ) {
        authService.register(request);
        return ResponseEntity
                .status(201)
                .body("Registration successful. Please verify your email.");
    }

    @AuthAudit(
            event = AuthAuditEvent.EMAIL_VERIFY,
            subject = AuditSubjectType.EMAIL
    )
    @GetMapping("/email-verify")
    public ResponseEntity<String> verifyEmail(@RequestParam String token) {
        authService.verifyEmail(token);
        return ResponseEntity.ok("Email verified successfully.");
    }

    @AuthAudit(
            event = AuthAuditEvent.EMAIL_VERIFICATION_RESEND,
            subject = AuditSubjectType.EMAIL
    )
    @PostMapping("/resend-verification")
    public ResponseEntity<Void> resendVerification(
            @RequestBody ResendVerificationRequest request
    ) {
        authService.resendVerification(request.email());
        return ResponseEntity.noContent().build();
    }

    // ---------- LOGIN ----------

    @AuthAudit(
            event = AuthAuditEvent.LOGIN,
            subject = AuditSubjectType.USER_ID
    )
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

        SecurityContextHolder.getContext().setAuthentication(authentication);

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

    // ---------- TOKEN ----------

    @AuthAudit(
            event = AuthAuditEvent.TOKEN_REFRESHED,
            subject = AuditSubjectType.ANONYMOUS
    )
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

    @AuthAudit(
            event = AuthAuditEvent.LOGOUT,
            subject = AuditSubjectType.USER_ID
    )
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        webAuthFacade.logout(request, response);
        return ResponseEntity.noContent().build();
    }

    // ---------- PASSWORD ----------

    @AuthAudit(
            event = AuthAuditEvent.PASSWORD_RESET_REQUEST,
            subject = AuditSubjectType.EMAIL
    )
    @PostMapping("/forgot-password")
    public ResponseEntity<Void> forgotPassword(
            @RequestBody ForgotPasswordRequest request
    ) {
        authService.initiatePasswordReset(request.email());
        return ResponseEntity.noContent().build();
    }

    @AuthAudit(
            event = AuthAuditEvent.PASSWORD_RESET_RESULT,
            subject = AuditSubjectType.EMAIL
    )
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
