package com.jaypal.authapp.service.auth;

import com.jaypal.authapp.dto.auth.AuthLoginResult;
import com.jaypal.authapp.dto.auth.RefreshTokenRequest;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import com.jaypal.authapp.service.auth.web.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Refactored WebAuthFacade with delegated operations.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class WebAuthFacade {

    private final AuthService authService;
    private final LoginWebOperation loginWebOperation;
    private final RefreshWebOperation refreshWebOperation;
    private final LogoutWebOperation logoutWebOperation;

    public AuthLoginResult login(AuthPrincipal principal, HttpServletResponse response) {
        if (principal == null) {
            log.error("Login aborted. AuthPrincipal is null");
            throw new IllegalArgumentException("AuthPrincipal must not be null");
        }

        return loginWebOperation.execute(principal, response, authService);
    }

    public AuthLoginResult refresh(
            HttpServletRequest request,
            HttpServletResponse response,
            RefreshTokenRequest body
    ) {
        return refreshWebOperation.execute(request, response, body, authService);
    }

    public void logout(
            AuthPrincipal principal,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        logoutWebOperation.execute(principal, request, response, authService);
    }
}