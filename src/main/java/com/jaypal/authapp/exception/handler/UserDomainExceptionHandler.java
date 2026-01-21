package com.jaypal.authapp.exception.handler;

import com.jaypal.authapp.domain.user.exception.InvalidRoleOperationException;
import com.jaypal.authapp.domain.user.exception.ResourceNotFoundException;
import com.jaypal.authapp.exception.response.ApiErrorResponseBuilder;
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
public class UserDomainExceptionHandler {

    private final ApiErrorResponseBuilder problemBuilder;

    public ResponseEntity<Map<String, Object>> handleInvalidRoleOperation(
            InvalidRoleOperationException ex,
            WebRequest request
    ) {
        return problemBuilder.build(
                HttpStatus.CONFLICT,
                "Invalid role operation",
                problemBuilder.resolveMessage(ex, "Invalid role operation."),
                request,
                "Invalid role operation attempted",
                false
        );
    }

    public ResponseEntity<Map<String, Object>> handleResourceNotFound(
            ResourceNotFoundException ex,
            WebRequest request
    ) {
        return problemBuilder.build(
                HttpStatus.NOT_FOUND,
                "Resource not found",
                problemBuilder.resolveMessage(ex, "The requested resource was not found."),
                request,
                "Resource not found",
                false
        );
    }
}