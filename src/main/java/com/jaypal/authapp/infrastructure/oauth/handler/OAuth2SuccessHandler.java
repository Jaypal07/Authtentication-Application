package com.jaypal.authapp.infrastructure.oauth.handler;

import com.jaypal.authapp.config.properties.FrontendProperties;
import com.jaypal.authapp.domain.audit.entity.*;
import com.jaypal.authapp.domain.audit.service.AuthAuditService;
import com.jaypal.authapp.dto.oauth.OAuthLoginResult;
import com.jaypal.authapp.infrastructure.audit.context.AuditContextHolder;
import com.jaypal.authapp.infrastructure.utils.CookieService;
import com.jaypal.authapp.service.oauth.OAuthLoginService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Objects;
import java.util.UUID;

/**
 * Responsibility: HTTP response only.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private static final long MAX_COOKIE_TTL = Integer.MAX_VALUE;

    private final OAuthLoginService oauthLoginService;
    private final CookieService cookieService;
    private final FrontendProperties frontendProperties;
    private final AuthAuditService auditService;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException {

        OAuth2AuthenticationToken token = validateAndExtractToken(authentication);

        OAuthLoginResult result = oauthLoginService.login(token);

        attachSecurityArtifacts(response, result);
        auditSuccess(token, result);

        response.sendRedirect(getSuccessRedirectUrl());
    }

    private OAuth2AuthenticationToken validateAndExtractToken(Authentication authentication) {
        Objects.requireNonNull(authentication, "Authentication cannot be null");

        if (!(authentication instanceof OAuth2AuthenticationToken token)) {
            throw new IllegalStateException("Invalid OAuth2 token type");
        }

        return token;
    }

    private void attachSecurityArtifacts(HttpServletResponse response, OAuthLoginResult result) {
        int refreshTtl = result.refreshTtlSeconds() > MAX_COOKIE_TTL
                ? Integer.MAX_VALUE
                : (int) result.refreshTtlSeconds();

        cookieService.attachRefreshCookie(response, result.refreshToken(), refreshTtl);
        cookieService.addNoStoreHeader(response);
    }

    private void auditSuccess(OAuth2AuthenticationToken token, OAuthLoginResult result) {
        try {
            UUID userId = result.userId();

            auditService.record(
                    AuditCategory.AUTHENTICATION,
                    AuthAuditEvent.OAUTH_LOGIN,
                    AuditOutcome.SUCCESS,
                    AuditActor.userId(userId.toString()),
                    AuditSubject.userId(userId.toString()),
                    null,
                    resolveProvider(token),
                    AuditContextHolder.getContext()
            );

        } catch (Exception ex) {
            log.error("Audit failure", ex);
        }
    }

    private AuthProvider resolveProvider(OAuth2AuthenticationToken token) {
        try {
            return AuthProvider.valueOf(token.getAuthorizedClientRegistrationId().toUpperCase());
        } catch (Exception e) {
            return AuthProvider.SYSTEM;
        }
    }

    private String getSuccessRedirectUrl() {
        String redirectUrl = frontendProperties.getSuccessRedirect();
        if (redirectUrl == null || redirectUrl.isBlank()) {
            throw new IllegalStateException("Frontend success redirect not configured");
        }
        return redirectUrl;
    }
}
