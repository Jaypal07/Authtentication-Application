package com.jaypal.authapp.exception.response;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Factory for creating RFC 7807 Problem Detail response bodies.
 * Follows Single Responsibility Principle.
 */
@Component
public class ErrorDetailFactory {

    private static final String TYPE_ABOUT_BLANK = "about:blank";

    public Map<String, Object> create(
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
}