package com.jaypal.authapp.auth.api;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.domain.AuditSubjectType;
import com.jaypal.authapp.audit.domain.AuthAuditEvent;
import com.jaypal.authapp.audit.domain.AuthProvider;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import com.jaypal.authapp.token.application.RefreshTokenService;
import com.jaypal.authapp.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthLogoutController {

    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;

    @AuthAudit(
            event = AuthAuditEvent.TOKEN_REVOKED,
            subject = AuditSubjectType.USER_ID,
            provider = AuthProvider.SYSTEM
    )
    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(
            @AuthenticationPrincipal AuthPrincipal principal
    ) {
        if (principal == null) {
            return ResponseEntity.noContent().build();
        }

        userRepository.findById(principal.getUserId()).ifPresent(user -> {
            user.bumpPermissionVersion();
            refreshTokenService.revokeAllForUser(user.getId());
        });

        return ResponseEntity.noContent().build();
    }
}

