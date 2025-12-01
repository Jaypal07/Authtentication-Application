package com.jaypal.authapp.exceptions;

import com.jaypal.authapp.dtos.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;


@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ResourceNotFoundExceptions.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFoundException(ResourceNotFoundExceptions ex, WebRequest request) {
        HttpStatus status = HttpStatus.NOT_FOUND;
        // Extract the request path from WebRequest if possible
        String path = (request instanceof ServletWebRequest) ?
                ((ServletWebRequest) request).getRequest().getRequestURI() : "N/A";
        // Build the robust ErrorResponse object
        ErrorResponse errorResponse = new ErrorResponse(
                path,                           // The API path called
                status.value(),                 // 404
                status.getReasonPhrase(),       // "Not Found"
                ex.getMessage()                 // The specific message from your exception
        );

        // Return the response entity with the correct HTTP Status
        return new ResponseEntity<>(errorResponse, status);
    }


    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException ex, WebRequest request) {
        HttpStatus status = HttpStatus.BAD_REQUEST;
        String path = (request instanceof ServletWebRequest) ?
                ((ServletWebRequest) request).getRequest().getRequestURI() : "N/A";
        ErrorResponse errorResponse = new ErrorResponse(
                path,
                status.value(),
                status.getReasonPhrase(),
                ex.getMessage()
        );
        return new ResponseEntity<>(errorResponse, status);
    }

}
