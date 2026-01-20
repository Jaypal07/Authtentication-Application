package com.jaypal.authapp.exception.response;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;

import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Builder for RFC 7807 Problem Details responses.
 * Provides consistent error response structure across the application.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ProblemResponseBuilder {

    private static final String CORRELATION_HEADER = "X-Correlation-Id";
    private static final String TYPE_ABOUT_BLANK = "about:blank";

    /**
     * Creates a standard problem response with correlation tracking.
     */
    public ResponseEntity<Map<String, Object>> build(
            HttpStatus status,
            String title,
            String detail,
            WebRequest request,
            String logMessage,
            boolean serverError
    ) {
        String correlationId = resolveCorrelationId(request);
        String path = extractPath(request);

        logError(serverError, logMessage, correlationId, path);

        Map<String, Object> body = buildResponseBody(status, title, detail, path, correlationId);

        return ResponseEntity
                .status(status)
                .header(CORRELATION_HEADER, correlationId)
                .body(body);
    }

    /**
     * Creates a validation error response with field-level errors.
     */
    public ResponseEntity<Map<String, Object>> buildValidationError(
            Map<String, String> fieldErrors,
            WebRequest request
    ) {
        String correlationId = resolveCorrelationId(request);
        String path = extractPath(request);

        log.warn("Validation failure | path={} | errors={}", path, fieldErrors.size());

        Map<String, Object> body = new HashMap<>();
        body.put("type", URI.create(TYPE_ABOUT_BLANK));
        body.put("title", "Validation failed");
        body.put("status", HttpStatus.BAD_REQUEST.value());
        body.put("detail", "Request validation failed");
        body.put("errors", fieldErrors);
        body.put("instance", path);
        body.put("correlationId", correlationId);
        body.put("timestamp", Instant.now().toString());

        return ResponseEntity
                .badRequest()
                .header(CORRELATION_HEADER, correlationId)
                .body(body);
    }

    /**
     * Resolves a safe error message from an exception.
     */
    public String resolveMessage(Throwable ex, String defaultMessage) {
        return (ex != null && ex.getMessage() != null && !ex.getMessage().isBlank())
                ? ex.getMessage()
                : defaultMessage;
    }

    /**
     * Extracts the request path from the web request.
     */
    public String extractPath(WebRequest request) {
        if (request instanceof ServletWebRequest servletRequest) {
            return servletRequest.getRequest().getRequestURI();
        }
        return "N/A";
    }

    /**
     * Resolves or generates a correlation ID for request tracking.
     */
    public String resolveCorrelationId(WebRequest request) {
        if (request instanceof ServletWebRequest swr) {
            String existing = swr.getRequest().getHeader(CORRELATION_HEADER);
            if (existing != null && !existing.isBlank()) {
                return existing;
            }
        }
        return UUID.randomUUID().toString();
    }

    /**
     * Builds the response body map following RFC 7807 structure.
     */
    private Map<String, Object> buildResponseBody(
            HttpStatus status,
            String title,
            String detail,
            String path,
            String correlationId
    ) {
        Map<String, Object> body = new HashMap<>();
        body.put("type", URI.create(TYPE_ABOUT_BLANK));
        body.put("title", title);
        body.put("status", status.value());
        body.put("detail", detail);
        body.put("instance", path);
        body.put("correlationId", correlationId);
        body.put("timestamp", Instant.now().toString());
        return body;
    }

    /**
     * Logs the error appropriately based on severity.
     */
    private void logError(boolean serverError, String logMessage, String correlationId, String path) {
        if (serverError) {
            log.error("{} | correlationId={} | path={}", logMessage, correlationId, path);
        } else {
            log.warn("{} | correlationId={} | path={}", logMessage, correlationId, path);
        }
    }
}