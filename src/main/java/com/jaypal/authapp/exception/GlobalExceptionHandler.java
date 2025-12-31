package com.jaypal.authapp.exception;

import com.jaypal.authapp.audit.model.AuthAuditEvent;
import com.jaypal.authapp.audit.service.AuthAuditService;
import com.jaypal.authapp.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    private final AuthAuditService authAuditService;

    // ---------------------------------------------------------
    // Utility Methods
    // ---------------------------------------------------------
    private String extractPath(WebRequest request) {
        if (request instanceof ServletWebRequest servletRequest) {
            return servletRequest.getRequest().getRequestURI();
        }
        return "N/A";
    }

    private ResponseEntity<ErrorResponse> buildErrorResponse(
            String message,
            HttpStatus status,
            String path
    ) {
        ErrorResponse errorResponse = new ErrorResponse(
                path,
                status.value(),
                status.getReasonPhrase(),
                message
        );
        return ResponseEntity.status(status).body(errorResponse);
    }

    // ---------------------------------------------------------
    // Authentication Exceptions
    // ---------------------------------------------------------

    // 1. Specifically handle unverified accounts
    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<ErrorResponse> handleDisabled(
            DisabledException ex,
            HttpServletRequest request
    ) {
        log.warn("Unverified login attempt at {}: {}", request.getRequestURI(), ex.getMessage());

        return buildErrorResponse(
                "Please verify your email address before logging in.",
                HttpStatus.FORBIDDEN, // 403 is standard for "we know who you are but you aren't allowed yet"
                request.getRequestURI()
        );
    }

    // 2. Handle Bad Credentials (Wrong password/email)
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentials(
            BadCredentialsException ex,
            HttpServletRequest request
    ) {
        authAuditService.log(
                null,
                AuthAuditEvent.LOGIN_FAILURE,
                "LOCAL",
                request,
                false,
                "Invalid username or password"
        );

        log.warn("Bad credentials at {}: {}", request.getRequestURI(), ex.getMessage());

        return buildErrorResponse(
                "Invalid username or password",
                HttpStatus.UNAUTHORIZED,
                request.getRequestURI()
        );
    }

    // 3. Catch remaining Auth issues (UsernameNotFound, Locked, etc.)
    @ExceptionHandler({UsernameNotFoundException.class, LockedException.class})
    public ResponseEntity<ErrorResponse> handleOtherAuthExceptions(
            Exception ex,
            HttpServletRequest request
    ) {
        log.warn("Authentication error at {}: {}", request.getRequestURI(), ex.getMessage());

        return buildErrorResponse(
                ex.getMessage(),
                HttpStatus.UNAUTHORIZED,
                request.getRequestURI()
        );
    }

    // ---------------------------------------------------------
    // Authorization / Access Denied
    // ---------------------------------------------------------
    @ExceptionHandler({AccessDeniedException.class, AuthorizationDeniedException.class})
    public ResponseEntity<ErrorResponse> handleAccessDenied(
            Exception ex,
            WebRequest request
    ) {
        String path = extractPath(request);
        log.warn("Access denied at {}: {}", path, ex.getMessage());

        return buildErrorResponse(
                "You do not have permission to access this resource",
                HttpStatus.FORBIDDEN,
                path
        );
    }

    // ---------------------------------------------------------
    // Validation & Data Integrity
    // ---------------------------------------------------------
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> handleDataIntegrityViolation(
            DataIntegrityViolationException ex,
            WebRequest request
    ) {
        String path = extractPath(request);
        String message = "Data integrity error";

        if (ex.getRootCause() != null) {
            String rootMessage = ex.getRootCause().getMessage().toLowerCase();
            if (rootMessage.contains("unique") && rootMessage.contains("email")) {
                message = "Email already exists";
            }
        }

        return buildErrorResponse(message, HttpStatus.BAD_REQUEST, path);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationExceptions(
            MethodArgumentNotValidException ex,
            WebRequest request
    ) {
        String path = extractPath(request);
        Map<String, String> fieldErrors = new HashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            fieldErrors.put(error.getField(), error.getDefaultMessage());
        }

        return buildErrorResponse(fieldErrors.toString(), HttpStatus.BAD_REQUEST, path);
    }

    // ---------------------------------------------------------
    // Fallbacks
    // ---------------------------------------------------------
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFound(
            ResourceNotFoundException ex,
            WebRequest request
    ) {
        return buildErrorResponse(ex.getMessage(), HttpStatus.NOT_FOUND, extractPath(request));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(
            Exception ex,
            WebRequest request
    ) {
        String path = extractPath(request);
        log.error("Unexpected error at {}: {}", path, ex.getMessage(), ex);

        return buildErrorResponse(
                "An unexpected error occurred.",
                HttpStatus.INTERNAL_SERVER_ERROR,
                path
        );
    }
}