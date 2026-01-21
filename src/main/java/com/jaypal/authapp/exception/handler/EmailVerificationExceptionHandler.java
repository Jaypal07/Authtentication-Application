package com.jaypal.authapp.exception.handler;

import com.jaypal.authapp.domain.user.exception.EmailAlreadyExistsException;
import com.jaypal.authapp.exception.auth.EmailAlreadyVerifiedException;
import com.jaypal.authapp.exception.auth.EmailDeliveryFailedException;
import com.jaypal.authapp.exception.auth.SilentEmailVerificationResendException;
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
public class EmailVerificationExceptionHandler {

    private final ProblemResponseBuilder problemBuilder;

    public ResponseEntity<Map<String, Object>> handleEmailAlreadyExists(
            EmailAlreadyExistsException ex,
            WebRequest request
    ) {
        return problemBuilder.build(
                HttpStatus.CONFLICT,
                "Email already exists",
                problemBuilder.resolveMessage(ex, "An account with this email already exists."),
                request,
                "Duplicate email registration attempt",
                false
        );
    }

    public ResponseEntity<Map<String, Object>> handleEmailAlreadyVerified(
            EmailAlreadyVerifiedException ex,
            WebRequest request
    ) {
        return problemBuilder.build(
                HttpStatus.CONFLICT,
                "Email already verified",
                problemBuilder.resolveMessage(ex, "This email address is already verified."),
                request,
                "Email verification for already-verified account",
                false
        );
    }

    public ResponseEntity<Map<String, Object>> handleVerificationTokenFailures(
            RuntimeException ex,
            WebRequest request
    ) {
        return problemBuilder.build(
                HttpStatus.BAD_REQUEST,
                "Verification failed",
                problemBuilder.resolveMessage(ex, "Verification token is invalid or expired."),
                request,
                "Email verification failure: " + ex.getClass().getSimpleName(),
                false
        );
    }

    public ResponseEntity<Void> handleEmailNotRegistered() {
        log.debug("Email verification resend call for non-existent email");
        return ResponseEntity.ok().build();
    }

    public ResponseEntity<Void> handleSilentVerificationResend(
            SilentEmailVerificationResendException ex,
            WebRequest request
    ) {
        log.debug(
                "Silent verification resend | path={} | reason={}",
                problemBuilder.extractPath(request),
                ex.getMessage()
        );
        return ResponseEntity.ok().build();
    }

    public ResponseEntity<Map<String, Object>> handleEmailDeliveryFailed(
            EmailDeliveryFailedException ex,
            WebRequest request
    ) {
        return problemBuilder.build(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Email delivery failed",
                "We were unable to send the verification email. Please try again later.",
                request,
                "Email delivery failure",
                true
        );
    }
}
