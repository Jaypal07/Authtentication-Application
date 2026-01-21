package com.jaypal.authapp.exception;

import com.jaypal.authapp.exception.audit.AuditLogger;
import com.jaypal.authapp.exception.handler.*;
import com.jaypal.authapp.exception.response.ProblemResponseBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.util.Map;

/**
 * Refactored GlobalExceptionHandler following SOLID principles.
 * Delegates exception handling to specialized handler components.
 *
 * Benefits:
 * - Single Responsibility: Each handler focuses on one exception category
 * - Open/Closed: Easy to add new exception handlers without modifying this class
 * - Testability: Individual handlers can be unit tested in isolation
 * - Maintainability: Clear separation of concerns
 */
@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    private final AuditLogger auditLogger;
    private final ProblemResponseBuilder problemBuilder;

    // Specialized handlers
    private final AuthorizationExceptionHandler authorizationHandler;
    private final AuthenticationExceptionHandler authenticationHandler;
    private final EmailVerificationExceptionHandler emailVerificationHandler;
    private final PasswordTokenExceptionHandler passwordTokenHandler;
    private final UserDomainExceptionHandler userDomainHandler;
    private final ValidationExceptionHandler validationHandler;
    private final InfrastructureExceptionHandler infrastructureHandler;

    /* =====================
       AUTHORIZATION
       ===================== */

    @ExceptionHandler({
            org.springframework.security.access.AccessDeniedException.class,
            org.springframework.security.authorization.AuthorizationDeniedException.class
    })
    public ResponseEntity<Map<String, Object>> handleAccessDenied(
            Exception ex,
            WebRequest request
    ) {
        return authorizationHandler.handleAccessDenied(ex, request, auditLogger);
    }

    /* =====================
       AUTHENTICATION
       ===================== */

    @ExceptionHandler(org.springframework.security.authentication.BadCredentialsException.class)
    public ResponseEntity<Map<String, Object>> handleBadCredentials(
            org.springframework.security.authentication.BadCredentialsException ex,
            WebRequest request
    ) {
        return authenticationHandler.handleBadCredentials(ex, request);
    }

    @ExceptionHandler(com.jaypal.authapp.exception.auth.AuthenticatedUserMissingException.class)
    public ResponseEntity<Map<String, Object>> handleAuthenticatedUserMissing(
            com.jaypal.authapp.exception.auth.AuthenticatedUserMissingException ex,
            WebRequest request
    ) {
        return authenticationHandler.handleAuthenticatedUserMissing(ex, request);
    }

    @ExceptionHandler(com.jaypal.authapp.domain.user.exception.UserAccountDisabledException.class)
    public ResponseEntity<Map<String, Object>> handleAccountDisabled(
            com.jaypal.authapp.domain.user.exception.UserAccountDisabledException ex,
            WebRequest request
    ) {
        return authenticationHandler.handleAccountDisabled(ex, request);
    }

    @ExceptionHandler(com.jaypal.authapp.exception.auth.EmailNotVerifiedException.class)
    public ResponseEntity<Map<String, Object>> handleEmailNotVerified(
            com.jaypal.authapp.exception.auth.EmailNotVerifiedException ex,
            WebRequest request
    ) {
        return authenticationHandler.handleEmailNotVerified(ex, request);
    }

    @ExceptionHandler(org.springframework.security.authentication.LockedException.class)
    public ResponseEntity<Map<String, Object>> handleAccountLocked(
            org.springframework.security.authentication.LockedException ex,
            WebRequest request
    ) {
        return authenticationHandler.handleAccountLocked(ex, request);
    }

    @ExceptionHandler(org.springframework.security.authentication.InternalAuthenticationServiceException.class)
    public ResponseEntity<Map<String, Object>> handleInternalAuthenticationServiceException(
            org.springframework.security.authentication.InternalAuthenticationServiceException ex,
            WebRequest request
    ) {
        return authenticationHandler.handleInternalAuthenticationServiceException(ex, request);
    }

    /* =====================
       EMAIL VERIFICATION
       ===================== */

    @ExceptionHandler(com.jaypal.authapp.domain.user.exception.EmailAlreadyExistsException.class)
    public ResponseEntity<Map<String, Object>> handleEmailAlreadyExists(
            com.jaypal.authapp.domain.user.exception.EmailAlreadyExistsException ex,
            WebRequest request
    ) {
        return emailVerificationHandler.handleEmailAlreadyExists(ex, request);
    }

    @ExceptionHandler(com.jaypal.authapp.exception.auth.EmailAlreadyVerifiedException.class)
    public ResponseEntity<Map<String, Object>> handleAlreadyVerified(
            com.jaypal.authapp.exception.auth.EmailAlreadyVerifiedException ex,
            WebRequest request
    ) {
        return emailVerificationHandler.handleEmailAlreadyVerified(ex, request);
    }

    @ExceptionHandler({
            com.jaypal.authapp.exception.auth.VerificationTokenExpiredException.class,
            com.jaypal.authapp.exception.auth.VerificationTokenInvalidException.class
    })
    public ResponseEntity<Map<String, Object>> handleVerificationTokenFailures(
            RuntimeException ex,
            WebRequest request
    ) {
        return emailVerificationHandler.handleVerificationTokenFailures(ex, request);
    }

    @ExceptionHandler(com.jaypal.authapp.exception.auth.EmailNotRegisteredException.class)
    public ResponseEntity<Void> swallowEmailNotRegistered() {
        return emailVerificationHandler.handleEmailNotRegistered();
    }

    @ExceptionHandler(com.jaypal.authapp.exception.auth.SilentEmailVerificationResendException.class)
    public ResponseEntity<Void> handleSilentVerificationResend(
            com.jaypal.authapp.exception.auth.SilentEmailVerificationResendException ex,
            WebRequest request
    ) {
        return emailVerificationHandler.handleSilentVerificationResend(ex, request);
    }

    @ExceptionHandler(com.jaypal.authapp.exception.auth.EmailDeliveryFailedException.class)
    public ResponseEntity<Map<String, Object>> handleEmailDeliveryFailed(
            com.jaypal.authapp.exception.auth.EmailDeliveryFailedException ex,
            WebRequest request
    ) {
        return emailVerificationHandler.handleEmailDeliveryFailed(ex, request);
    }

    /* =====================
       PASSWORD & TOKENS
       ===================== */

    @ExceptionHandler({
            com.jaypal.authapp.exception.auth.PasswordPolicyViolationException.class,
            com.jaypal.authapp.exception.auth.PasswordResetTokenInvalidException.class,
            com.jaypal.authapp.exception.auth.PasswordResetTokenExpiredException.class
    })
    public ResponseEntity<Map<String, Object>> handlePasswordFailures(
            RuntimeException ex,
            WebRequest request
    ) {
        return passwordTokenHandler.handlePasswordFailures(ex, request);
    }

    @ExceptionHandler({
            com.jaypal.authapp.domain.token.exception.RefreshTokenExpiredException.class,
            com.jaypal.authapp.domain.token.exception.RefreshTokenNotFoundException.class,
            com.jaypal.authapp.domain.token.exception.RefreshTokenRevokedException.class,
            com.jaypal.authapp.domain.token.exception.RefreshTokenUserMismatchException.class,
            com.jaypal.authapp.domain.token.exception.RefreshTokenException.class,
            com.jaypal.authapp.exception.auth.InvalidRefreshTokenException.class,
            com.jaypal.authapp.exception.auth.MissingRefreshTokenException.class
    })
    public ResponseEntity<Map<String, Object>> handleRefreshTokenFailures(
            RuntimeException ex,
            WebRequest request
    ) {
        return passwordTokenHandler.handleRefreshTokenFailures(ex, request);
    }

    /* =====================
       USER DOMAIN
       ===================== */

    @ExceptionHandler(com.jaypal.authapp.domain.user.exception.InvalidRoleOperationException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidRoleOperation(
            com.jaypal.authapp.domain.user.exception.InvalidRoleOperationException ex,
            WebRequest request
    ) {
        return userDomainHandler.handleInvalidRoleOperation(ex, request);
    }

    @ExceptionHandler(com.jaypal.authapp.domain.user.exception.ResourceNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleResourceNotFound(
            com.jaypal.authapp.domain.user.exception.ResourceNotFoundException ex,
            WebRequest request
    ) {
        return userDomainHandler.handleResourceNotFound(ex, request);
    }

    /* =====================
       VALIDATION
       ===================== */

    @ExceptionHandler(org.springframework.web.bind.MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(
            org.springframework.web.bind.MethodArgumentNotValidException ex,
            WebRequest request
    ) {
        return validationHandler.handleMethodArgumentNotValid(ex, request);
    }

    @ExceptionHandler(org.springframework.web.method.annotation.HandlerMethodValidationException.class)
    public ResponseEntity<Map<String, Object>> handleHandlerMethodValidation(
            org.springframework.web.method.annotation.HandlerMethodValidationException ex,
            WebRequest request
    ) {
        return validationHandler.handleHandlerMethodValidation(ex, request);
    }

    @ExceptionHandler(jakarta.validation.ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> handleConstraintViolation(
            jakarta.validation.ConstraintViolationException ex,
            WebRequest request
    ) {
        return validationHandler.handleConstraintViolation(ex, request);
    }

    @ExceptionHandler(org.springframework.web.method.annotation.MethodArgumentTypeMismatchException.class)
    public ResponseEntity<Map<String, Object>> handleMethodArgumentTypeMismatch(
            org.springframework.web.method.annotation.MethodArgumentTypeMismatchException ex,
            WebRequest request
    ) {
        return validationHandler.handleMethodArgumentTypeMismatch(ex, request);
    }

    /* =====================
       INFRASTRUCTURE
       ===================== */

    @ExceptionHandler(org.springframework.dao.DataIntegrityViolationException.class)
    public ResponseEntity<Map<String, Object>> handleDataIntegrity(
            org.springframework.dao.DataIntegrityViolationException ex,
            WebRequest request
    ) {
        return infrastructureHandler.handleDataIntegrity(ex, request);
    }

    @ExceptionHandler(com.jaypal.authapp.infrastructure.ratelimit.RateLimitExceededException.class)
    public ResponseEntity<Map<String, Object>> handleRateLimit(
            com.jaypal.authapp.infrastructure.ratelimit.RateLimitExceededException ex,
            WebRequest request
    ) {
        return infrastructureHandler.handleRateLimit(ex, request);
    }

    @ExceptionHandler(org.springframework.web.servlet.resource.NoResourceFoundException.class)
    public ResponseEntity<Map<String, Object>> handleNoResource(
            org.springframework.web.servlet.resource.NoResourceFoundException ex,
            WebRequest request
    ) {
        return infrastructureHandler.handleNoResource(ex, request);
    }

    @ExceptionHandler(org.springframework.http.converter.HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleNotReadable(
            org.springframework.http.converter.HttpMessageNotReadableException ex,
            WebRequest request
    ) {
        return infrastructureHandler.handleHttpMessageNotReadable(ex, request);
    }

    @ExceptionHandler(org.springframework.web.bind.MissingServletRequestParameterException.class)
    public ResponseEntity<Map<String, Object>> handleMissingRequestParam(
            org.springframework.web.bind.MissingServletRequestParameterException ex,
            WebRequest request
    ) {
        return infrastructureHandler.handleMissingRequestParameter(ex, request);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(
            IllegalArgumentException ex,
            WebRequest request
    ) {
        return infrastructureHandler.handleIllegalArgument(ex, request);
    }

    @ExceptionHandler(org.springframework.web.HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<org.springframework.http.ProblemDetail> handleMethodNotSupported(
            org.springframework.web.HttpRequestMethodNotSupportedException ex,
            WebRequest request
    ) {
        return infrastructureHandler.handleMethodNotSupported(ex, request);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGeneric(
            Exception ex,
            WebRequest request
    ) {
        return infrastructureHandler.handleGenericException(ex, request);
    }
}