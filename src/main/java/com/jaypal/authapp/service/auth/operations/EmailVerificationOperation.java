package com.jaypal.authapp.service.auth.operations;

import com.jaypal.authapp.domain.audit.entity.AuthFailureReason;
import com.jaypal.authapp.exception.auth.VerificationTokenInvalidException;
import com.jaypal.authapp.infrastructure.audit.context.AuditContextHolder;
import com.jaypal.authapp.service.auth.EmailVerificationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class EmailVerificationOperation {

    private final EmailVerificationService emailVerificationService;

    public void verify(String token) {
        if (token == null || token.isBlank()) {
            throw new VerificationTokenInvalidException();
        }

        log.debug("Email verification requested");
        emailVerificationService.verifyEmail(token);
    }

    public void resend(String email) {
        if (email == null || email.isBlank()) {
            log.warn("Resend verification called with blank email");
            return;
        }

        boolean sent = emailVerificationService.resendVerificationToken(email);

        if (!sent) {
            log.debug("Resend verification requested for already-verified user: {}", email);
            AuditContextHolder.markRejection(AuthFailureReason.EMAIL_ALREADY_VERIFIED);
        } else {
            log.debug("Verification email sent to {}", email);
        }
    }
}