package com.jaypal.authapp.service.auth.operations;

import com.jaypal.authapp.domain.user.entity.PermissionType;
import com.jaypal.authapp.domain.user.entity.User;
import com.jaypal.authapp.domain.user.repository.UserRepository;
import com.jaypal.authapp.domain.user.service.PermissionService;
import com.jaypal.authapp.dto.auth.AuthLoginResult;
import com.jaypal.authapp.exception.auth.AuthenticatedUserMissingException;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import com.jaypal.authapp.service.auth.TokenIssuer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class LoginOperation {

    private final UserRepository userRepository;
    private final TokenIssuer tokenIssuer;

    public AuthLoginResult execute(AuthPrincipal principal) {
        UUID userId = principal.getUserId();

        User user = userRepository.findById(userId)
                .orElseThrow(AuthenticatedUserMissingException::new);

        validateUserEnabled(user, userId);

        return tokenIssuer.issueTokens(user);
    }

    private void validateUserEnabled(User user, UUID userId) {
        if (!user.isEnabled()) {
            log.warn("Login blocked for disabled user. userId={}", userId);
            throw new AuthenticatedUserMissingException();
        }
    }
}