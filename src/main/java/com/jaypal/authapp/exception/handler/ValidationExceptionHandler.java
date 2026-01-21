package com.jaypal.authapp.exception.handler;

import com.jaypal.authapp.exception.response.ProblemResponseBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class ValidationExceptionHandler {

    private final ProblemResponseBuilder problemBuilder;

    public ResponseEntity<Map<String, Object>> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex,
            WebRequest request
    ) {
        Map<String, String> errors = extractFieldErrors(ex);
        return problemBuilder.buildValidationError(errors, request);
    }

    public ResponseEntity<Map<String, Object>> handleHandlerMethodValidation(
            HandlerMethodValidationException ex,
            WebRequest request
    ) {
        Map<String, String> errors = extractParameterErrors(ex);
        return problemBuilder.buildValidationError(errors, request);
    }

    public ResponseEntity<Map<String, Object>> handleConstraintViolation(
            jakarta.validation.ConstraintViolationException ex,
            WebRequest request
    ) {
        Map<String, String> errors = extractConstraintViolations(ex);
        return problemBuilder.buildValidationError(errors, request);
    }

    public ResponseEntity<Map<String, Object>> handleMethodArgumentTypeMismatch(
            MethodArgumentTypeMismatchException ex,
            WebRequest request
    ) {
        String detail = buildTypeMismatchDetail(ex);

        return problemBuilder.build(
                HttpStatus.BAD_REQUEST,
                "Invalid request parameter",
                detail,
                request,
                "Method argument type mismatch: " + ex.getName(),
                false
        );
    }

    private Map<String, String> extractFieldErrors(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            errors.put(error.getField(), error.getDefaultMessage());
        }
        return errors;
    }

    private Map<String, String> extractParameterErrors(HandlerMethodValidationException ex) {
        Map<String, String> errors = new HashMap<>();

        ex.getParameterValidationResults().forEach(result -> {
            String paramName = result.getMethodParameter().getParameterName();
            result.getResolvableErrors().forEach(error -> {
                errors.put(paramName, error.getDefaultMessage());
            });
        });

        return errors;
    }

    private Map<String, String> extractConstraintViolations(
            jakarta.validation.ConstraintViolationException ex
    ) {
        Map<String, String> errors = new HashMap<>();

        ex.getConstraintViolations().forEach(violation -> {
            String propertyPath = violation.getPropertyPath() != null
                    ? violation.getPropertyPath().toString()
                    : "parameter";
            errors.put(propertyPath, violation.getMessage());
        });

        return errors;
    }

    private String buildTypeMismatchDetail(MethodArgumentTypeMismatchException ex) {
        String parameterName = ex.getName();
        Object value = ex.getValue();
        Class<?> requiredType = ex.getRequiredType();

        String detail = (requiredType != null)
                ? "Parameter '%s' must be of type '%s'."
                .formatted(parameterName, requiredType.getSimpleName())
                : "Invalid value for parameter '%s'.".formatted(parameterName);

        if (value != null) {
            detail += " Provided value: '%s'.".formatted(value);
        }

        return detail;
    }
}
