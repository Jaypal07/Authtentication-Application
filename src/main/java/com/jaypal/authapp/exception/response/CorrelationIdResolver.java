package com.jaypal.authapp.exception.response;

import org.springframework.stereotype.Component;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;

import java.util.UUID;

/**
 * Resolves or generates correlation IDs for request tracking.
 * Follows Single Responsibility Principle.
 */
@Component
public class CorrelationIdResolver {

    private static final String CORRELATION_HEADER = "X-Correlation-Id";

    public String resolve(WebRequest request) {
        if (request instanceof ServletWebRequest servletWebRequest) {
            String existingId = servletWebRequest.getRequest().getHeader(CORRELATION_HEADER);
            if (existingId != null && !existingId.isBlank()) {
                return existingId;
            }
        }
        return generateCorrelationId();
    }

    private String generateCorrelationId() {
        return UUID.randomUUID().toString();
    }
}
