package com.jaypal.authapp.exception.handler;

import com.jaypal.authapp.domain.user.exception.UserAccountDisabledException;
import com.jaypal.authapp.exception.auth.AuthenticatedUserMissingException;
import com.jaypal.authapp.exception.auth.EmailNotVerifiedException;
import com.jaypal.authapp.exception.response.ApiErrorResponseBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;

import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthenticationExceptionHandler {

    private final ApiErrorResponseBuilder problemBuilder;

    public ResponseEntity<Map<String, Object>> handleBadCredentials(
            BadCredentialsException ex,
            WebRequest request
    ) {
        return problemBuilder.build(
                HttpStatus.UNAUTHORIZED,
                "Invalid credentials",
                problemBuilder.resolveMessage(ex, "The email or password you entered is incorrect."),
                request,
                "Authentication failure: invalid credentials",
                false
        );
    }

    public ResponseEntity<Map<String, Object>> handleAuthenticatedUserMissing(
            AuthenticatedUserMissingException ex,
            WebRequest request
    ) {
        return problemBuilder.build(
                HttpStatus.UNAUTHORIZED,
                "Authentication context invalid",
                problemBuilder.resolveMessage(ex, "Authentication state is no longer valid. Please log in again."),
                request,
                "Authenticated user missing from database",
                true
        );
    }

    public ResponseEntity<Map<String, Object>> handleAccountDisabled(
            UserAccountDisabledException ex,
            WebRequest request
    ) {
        return problemBuilder.build(
                HttpStatus.FORBIDDEN,
                "Account disabled",
                problemBuilder.resolveMessage(ex, "Your account has been disabled. Please contact support."),
                request,
                "Account disabled",
                false
        );
    }

    public ResponseEntity<Map<String, Object>> handleEmailNotVerified(
            EmailNotVerifiedException ex,
            WebRequest request
    ) {
        return problemBuilder.build(
                HttpStatus.FORBIDDEN,
                "Email not verified",
                problemBuilder.resolveMessage(ex, "Please verify your email address before logging in."),
                request,
                "Authentication failure: email not verified",
                false
        );
    }

    public ResponseEntity<Map<String, Object>> handleAccountLocked(
            LockedException ex,
            WebRequest request
    ) {
        return problemBuilder.build(
                HttpStatus.FORBIDDEN,
                "Account locked",
                problemBuilder.resolveMessage(ex, "Your account is locked. Please contact support."),
                request,
                "Authentication failure: account locked",
                false
        );
    }

    public ResponseEntity<Map<String, Object>> handleInternalAuthenticationServiceException(
            InternalAuthenticationServiceException ex,
            WebRequest request
    ) {
        Throwable cause = ex.getCause();

        if (isAccountDisabledException(cause)) {
            return createAccountDisabledResponse(cause, request);
        }

        if (cause instanceof LockedException) {
            return createAccountLockedResponse(cause, request);
        }

        if (cause instanceof BadCredentialsException) {
            return createBadCredentialsResponse(cause, request);
        }

        log.error("Unhandled InternalAuthenticationServiceException", ex);

        return problemBuilder.build(
                HttpStatus.UNAUTHORIZED,
                "Authentication failed",
                problemBuilder.resolveMessage(ex, "Authentication failed. Please try again."),
                request,
                "Authentication failure: internal service exception",
                true
        );
    }

    private boolean isAccountDisabledException(Throwable cause) {
        return cause instanceof DisabledException ||
                cause instanceof UserAccountDisabledException;
    }

    private ResponseEntity<Map<String, Object>> createAccountDisabledResponse(
            Throwable cause,
            WebRequest request
    ) {
        return problemBuilder.build(
                HttpStatus.FORBIDDEN,
                "Account disabled",
                problemBuilder.resolveMessage(cause, "Your account has been disabled. Please contact support."),
                request,
                "Authentication failure: account disabled (wrapped)",
                false
        );
    }

    private ResponseEntity<Map<String, Object>> createAccountLockedResponse(
            Throwable cause,
            WebRequest request
    ) {
        return problemBuilder.build(
                HttpStatus.FORBIDDEN,
                "Account locked",
                problemBuilder.resolveMessage(cause, "Your account is locked. Please contact support."),
                request,
                "Authentication failure: account locked (wrapped)",
                false
        );
    }

    private ResponseEntity<Map<String, Object>> createBadCredentialsResponse(
            Throwable cause,
            WebRequest request
    ) {
        return problemBuilder.build(
                HttpStatus.UNAUTHORIZED,
                "Invalid credentials",
                problemBuilder.resolveMessage(cause, "The email or password you entered is incorrect."),
                request,
                "Authentication failure: invalid credentials (wrapped)",
                false
        );
    }
}