package com.jaypal.authapp.infrastructure.audit.resolver;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

/**
 * Dedicated component for safely unwrapping exception chains.
 * Separated for testability and reusability.
 */
@Slf4j
@Component
public class ExceptionUnwrapper {

    private static final int MAX_DEPTH = 20; // Prevent infinite loops

    public Throwable unwrap(Throwable ex) {
        Set<Throwable> visited = new HashSet<>();
        Throwable current = ex;
        int depth = 0;

        while (shouldContinueUnwrapping(current, visited, depth)) {
            visited.add(current);

            if (current instanceof InternalAuthenticationServiceException) {
                current = current.getCause();
            } else {
                current = current.getCause();
            }

            depth++;
        }

        return current != null ? current : ex;
    }

    private boolean shouldContinueUnwrapping(Throwable current, Set<Throwable> visited, int depth) {
        return current != null &&
                current.getCause() != null &&
                !visited.contains(current) &&
                depth < MAX_DEPTH;
    }
}