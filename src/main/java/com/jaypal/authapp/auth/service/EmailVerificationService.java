package com.jaypal.authapp.auth.service;

import com.jaypal.authapp.auth.repositoty.EmailVerificationTokenRepository;
import com.jaypal.authapp.config.FrontendProperties;
import com.jaypal.authapp.exception.ResourceNotFoundException;
import com.jaypal.authapp.infrastructure.email.EmailService;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.model.VerificationToken;
import com.jaypal.authapp.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private final EmailVerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final FrontendProperties frontendProperties; // Use your existing config

    @Transactional
    public void createVerificationToken(User user) {
        String token = UUID.randomUUID().toString();
        VerificationToken verificationToken = new VerificationToken(token, user);
        tokenRepository.save(verificationToken);

        // Build link using your frontend properties or server base URL
        String verifyLink = frontendProperties.getBaseUrl() + "/email-verify?token=" + token;

        emailService.sendVerificationEmail(user.getEmail(), verifyLink);
    }

    @Transactional
    public void resendVerificationToken(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (user.isEnabled()) {
            throw new IllegalStateException("Account is already verified");
        }

        // 1. Remove any existing tokens for this user
        tokenRepository.deleteByUser(user);

        // 2. Generate and save new token
        String token = UUID.randomUUID().toString();
        VerificationToken verificationToken = new VerificationToken(token, user);
        tokenRepository.save(verificationToken);

        // 3. Send email
        String verifyLink = frontendProperties.getBaseUrl() + "/email-verify?token=" + token;
        emailService.sendVerificationEmail(user.getEmail(), verifyLink);
    }

    @Transactional
    public void verifyEmail(String token) {
        VerificationToken vToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new BadCredentialsException("Invalid or expired token"));

        if (vToken.getExpiryDate().isBefore(java.time.Instant.now())) {
            tokenRepository.delete(vToken);
            throw new BadCredentialsException("Token expired");
        }

        User user = vToken.getUser();
        user.enable(); // Uses your domain method
        userRepository.save(user);

        tokenRepository.delete(vToken);
    }
}
