package com.jaypal.authapp.exception.response;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Factory for creating validation error response bodies.
 * Follows Single Responsibility Principle.
 */
@Component
public class ValidationErrorFactory {

    private static final String TYPE_ABOUT_BLANK = "about:blank";

    public Map<String, Object> create(
            Map<String, String> fieldErrors,
            String path,
            String correlationId
    ) {
        Map<String, Object> body = new HashMap<>();
        body.put("type", URI.create(TYPE_ABOUT_BLANK));
        body.put("title", "Validation failed");
        body.put("status", HttpStatus.BAD_REQUEST.value());
        body.put("detail", "Request validation failed");
        body.put("errors", fieldErrors);
        body.put("instance", path);
        body.put("correlationId", correlationId);
        body.put("timestamp", Instant.now().toString());
        return body;
    }
}