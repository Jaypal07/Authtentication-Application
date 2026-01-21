package com.jaypal.authapp.service.auth.web;

import com.jaypal.authapp.dto.audit.AuditRequestContext;
import com.jaypal.authapp.infrastructure.audit.context.AuditContextHolder;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import com.jaypal.authapp.infrastructure.utils.CookieService;
import com.jaypal.authapp.infrastructure.utils.RefreshTokenExtractor;
import com.jaypal.authapp.service.auth.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class LogoutWebOperation {

    private final RefreshTokenExtractor refreshTokenExtractor;
    private final CookieService cookieService;

    public void execute(
            AuthPrincipal principal,
            HttpServletRequest request,
            HttpServletResponse response,
            AuthService authService
    ) {
        log.debug(
                "Logout flow started | userId={}",
                principal != null ? principal.getUserId() : "anonymous"
        );

        try {
            refreshTokenExtractor.extract(request)
                    .ifPresent(token -> {
                        enrichAuditContext(token, authService);
                        authService.logout(token);
                    });

        } catch (Exception ex) {
            log.warn(
                    "Logout error ignored | userId={} reason={}",
                    principal != null ? principal.getUserId() : "anonymous",
                    ex.getMessage()
            );
        } finally {
            cleanupResponse(response);

            log.debug(
                    "Logout flow completed | userId={}",
                    principal != null ? principal.getUserId() : "anonymous"
            );
        }
    }

    private void enrichAuditContext(String token, AuthService authService) {
        String userId = authService.resolveUserId(token);

        AuditRequestContext ctx = AuditContextHolder.getContext();
        if (ctx != null) {
            AuditContextHolder.setContext(
                    new AuditRequestContext(
                            ctx.ipAddress(),
                            ctx.userAgent(),
                            userId
                    )
            );
        }
    }

    private void cleanupResponse(HttpServletResponse response) {
        cookieService.clearRefreshCookie(response);
        cookieService.addNoStoreHeader(response);
    }
}