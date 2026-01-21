package com.jaypal.authapp.service.auth.web;

import com.jaypal.authapp.dto.auth.AuthLoginResult;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import com.jaypal.authapp.infrastructure.utils.CookieService;
import com.jaypal.authapp.service.auth.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class LoginWebOperation {

    private final CookieService cookieService;
    private final RefreshCookieAttacher cookieAttacher;

    public AuthLoginResult execute(
            AuthPrincipal principal,
            HttpServletResponse response,
            AuthService authService
    ) {
        log.debug("Login flow started | userId={}", principal.getUserId());

        AuthLoginResult result = authService.login(principal);

        log.debug(
                "Login successful | userId={} refreshExpiresAt={}",
                result.user().id(),
                result.refreshExpiresAtEpochSeconds()
        );

        cookieAttacher.attach(response, result);

        log.debug("Login flow completed | userId={}", principal.getUserId());
        return result;
    }
}