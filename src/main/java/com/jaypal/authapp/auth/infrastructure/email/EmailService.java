package com.jaypal.authapp.auth.infrastructure.email;

import org.springframework.stereotype.Service;

@Service
public interface EmailService {
    void sendPasswordResetEmail(String to, String resetLink);
    void sendVerificationEmail(String to, String verifyLink);
}

