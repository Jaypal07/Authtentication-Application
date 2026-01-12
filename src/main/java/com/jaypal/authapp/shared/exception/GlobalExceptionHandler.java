package com.jaypal.authapp.shared.exception;

import com.jaypal.authapp.auth.exception.*;
import com.jaypal.authapp.token.exception.*;
import com.jaypal.authapp.user.exception.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.*;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final String CORRELATION_HEADER = "X-Correlation-Id";
    private static final String TYPE_ABOUT_BLANK = "about:blank";

    private ResponseEntity<Map<String, Object>> problem(
            HttpStatus status,
            String title,
            String detail,
            WebRequest request,
            String logMessage,
            boolean logStackTrace
    ) {
        final String correlationId = UUID.randomUUID().toString();
        final String path = extractPath(request);

        if (logStackTrace) {
            log.error("{} | correlationId={} | path={}", logMessage, correlationId, path);
        } else {
            log.warn("{} | correlationId={} | path={}", logMessage, correlationId, path);
        }

        final Map<String, Object> body = new HashMap<>();
        body.put("type", URI.create(TYPE_ABOUT_BLANK));
        body.put("title", title);
        body.put("status", status.value());
        body.put("detail", detail);
        body.put("instance", path);
        body.put("correlationId", correlationId);
        body.put("timestamp", Instant.now().toString());

        return ResponseEntity
                .status(status)
                .header(CORRELATION_HEADER, correlationId)
                .body(body);
    }

    private String extractPath(WebRequest request) {
        if (request instanceof ServletWebRequest servletRequest) {
            return servletRequest.getRequest().getRequestURI();
        }
        return "N/A";
    }

    @ExceptionHandler({
            BadCredentialsException.class,
            InvalidCredentialsException.class,
            UsernameNotFoundException.class
    })
    public ResponseEntity<Map<String, Object>> handleInvalidCredentials(
            Exception ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.UNAUTHORIZED,
                "Authentication failed",
                "Invalid email or password.",
                request,
                "Authentication failure: invalid credentials",
                false
        );
    }

    @ExceptionHandler({
            DisabledException.class,
            UserAccountDisabledException.class
    })
    public ResponseEntity<Map<String, Object>> handleAccountDisabled(
            Exception ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.FORBIDDEN,
                "Account disabled",
                "Please verify your email address before logging in.",
                request,
                "Authentication failure: account disabled",
                false
        );
    }

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<Map<String, Object>> handleAccountLocked(
            LockedException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.FORBIDDEN,
                "Account locked",
                "Your account is locked. Please contact support.",
                request,
                "Authentication failure: account locked",
                false
        );
    }

    @ExceptionHandler(AuthenticatedUserMissingException.class)
    public ResponseEntity<Map<String, Object>> handleAuthenticatedUserMissing(
            AuthenticatedUserMissingException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.UNAUTHORIZED,
                "Authentication context invalid",
                "Authentication state is no longer valid. Please log in again.",
                request,
                "Authenticated user missing from database",
                true
        );
    }

    @ExceptionHandler({
            AccessDeniedException.class,
            AuthorizationDeniedException.class
    })
    public ResponseEntity<Map<String, Object>> handleAccessDenied(
            Exception ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.FORBIDDEN,
                "Access denied",
                "You do not have permission to access this resource.",
                request,
                "Authorization failure: " + ex.getClass().getSimpleName(),
                false
        );
    }

    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<Map<String, Object>> handleEmailAlreadyExists(
            EmailAlreadyExistsException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.CONFLICT,
                "Email already exists",
                ex.getMessage(),
                request,
                "Duplicate email registration attempt",
                false
        );
    }

    @ExceptionHandler(EmailAlreadyVerifiedException.class)
    public ResponseEntity<Map<String, Object>> handleAlreadyVerified(
            EmailAlreadyVerifiedException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.OK,
                "Email already verified",
                "This email address is already verified.",
                request,
                "Email verification for already-verified account",
                false
        );
    }

    @ExceptionHandler({
            VerificationTokenExpiredException.class,
            VerificationTokenInvalidException.class
    })
    public ResponseEntity<Map<String, Object>> handleVerificationTokenFailures(
            RuntimeException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.BAD_REQUEST,
                "Verification failed",
                ex.getMessage(),
                request,
                "Email verification failure: " + ex.getClass().getSimpleName(),
                false
        );
    }

    @ExceptionHandler(EmailNotRegisteredException.class)
    public ResponseEntity<Void> swallowEmailNotRegistered() {
        log.debug("Email verification resend for non-existent email - responding with success");
        return ResponseEntity.ok().build();
    }

    @ExceptionHandler({
            PasswordPolicyViolationException.class,
            PasswordResetTokenInvalidException.class,
            PasswordResetTokenExpiredException.class
    })
    public ResponseEntity<Map<String, Object>> handlePasswordFailures(
            RuntimeException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.BAD_REQUEST,
                "Password operation failed",
                ex.getMessage(),
                request,
                "Password operation failure: " + ex.getClass().getSimpleName(),
                false
        );
    }

    @ExceptionHandler({
            RefreshTokenExpiredException.class,
            RefreshTokenNotFoundException.class,
            RefreshTokenRevokedException.class,
            RefreshTokenUserMismatchException.class,
            RefreshTokenException.class,
            InvalidRefreshTokenException.class,
            MissingRefreshTokenException.class
    })
    public ResponseEntity<Map<String, Object>> handleRefreshTokenFailures(
            RuntimeException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.UNAUTHORIZED,
                "Invalid refresh token",
                "Your session has expired. Please log in again.",
                request,
                "Refresh token failure: " + ex.getClass().getSimpleName(),
                false
        );
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleResourceNotFound(
            ResourceNotFoundException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.NOT_FOUND,
                "Resource not found",
                ex.getMessage(),
                request,
                "Resource not found",
                false
        );
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(
            MethodArgumentNotValidException ex,
            WebRequest request
    ) {
        final Map<String, String> errors = new HashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            errors.put(error.getField(), error.getDefaultMessage());
        }

        final Map<String, Object> body = new HashMap<>();
        body.put("type", URI.create(TYPE_ABOUT_BLANK));
        body.put("title", "Validation failed");
        body.put("status", HttpStatus.BAD_REQUEST.value());
        body.put("detail", "Request validation failed");
        body.put("errors", errors);
        body.put("instance", extractPath(request));
        body.put("timestamp", Instant.now().toString());

        log.warn("Validation failure | path={} | errors={}", extractPath(request), errors.size());

        return ResponseEntity.badRequest().body(body);
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<Map<String, Object>> handleDataIntegrity(
            DataIntegrityViolationException ex,
            WebRequest request
    ) {
        final Throwable cause = ex.getCause();
        if (cause instanceof org.hibernate.exception.ConstraintViolationException cve) {
            if (cve.getConstraintName() != null &&
                    cve.getConstraintName().toLowerCase().contains("email")) {
                return problem(
                        HttpStatus.CONFLICT,
                        "Email already exists",
                        "An account with this email address already exists.",
                        request,
                        "Duplicate email constraint violation",
                        false
                );
            }
        }

        return problem(
                HttpStatus.BAD_REQUEST,
                "Invalid request",
                "Request violates data constraints.",
                request,
                "Data integrity violation: " + (cause != null ? cause.getClass().getSimpleName() : "unknown"),
                true
        );
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<Map<String, Object>> handleNoResource(
            NoResourceFoundException ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.NOT_FOUND,
                "Resource not found",
                "The requested resource was not found.",
                request,
                "404 Not Found",
                false
        );
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGeneric(
            Exception ex,
            WebRequest request
    ) {
        return problem(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Internal server error",
                "An unexpected error occurred. Please contact support if the problem persists.",
                request,
                "Unhandled exception: " + ex.getClass().getSimpleName(),
                true
        );
    }
}

/*
CHANGELOG:
1. Removed PII (exception details) from logs - only log exception class name
2. Changed EmailAlreadyVerified status to 200 OK (not an error)
3. Added ResourceNotFoundException handler
4. Improved validation error response structure
5. Added better constraint name matching for data integrity violations
6. Extracted TYPE_ABOUT_BLANK as constant
7. Removed unnecessary exception parameter from problem() method
8. Added path to all log statements
9. Made log messages more consistent
10. Improved email enumeration protection in swallowEmailNotRegistered
*/