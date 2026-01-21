package com.jaypal.authapp.exception.handler;

import com.jaypal.authapp.exception.response.ProblemResponseBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;

import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class PasswordTokenExceptionHandler {

    private final ProblemResponseBuilder problemBuilder;

    public ResponseEntity<Map<String, Object>> handlePasswordFailures(
            RuntimeException ex,
            WebRequest request
    ) {
        return problemBuilder.build(
                HttpStatus.BAD_REQUEST,
                "Password operation failed",
                problemBuilder.resolveMessage(ex, "Password operation failed."),
                request,
                "Password operation failure: " + ex.getClass().getSimpleName(),
                false
        );
    }

    public ResponseEntity<Map<String, Object>> handleRefreshTokenFailures(
            RuntimeException ex,
            WebRequest request
    ) {
        return problemBuilder.build(
                HttpStatus.UNAUTHORIZED,
                "Invalid refresh token",
                problemBuilder.resolveMessage(ex, "Your session has expired. Please log in again."),
                request,
                "Refresh token failure: " + ex.getClass().getSimpleName(),
                false
        );
    }
}
