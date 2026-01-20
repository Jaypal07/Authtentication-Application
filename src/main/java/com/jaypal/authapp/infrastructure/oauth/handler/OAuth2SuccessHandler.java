package com.jaypal.authapp.infrastructure.oauth.handler;

import com.jaypal.authapp.domain.audit.service.AuthAuditService;
import com.jaypal.authapp.infrastructure.audit.context.AuditContextHolder;
import com.jaypal.authapp.infrastructure.utils.CookieService;
import com.jaypal.authapp.config.properties.FrontendProperties;
import com.jaypal.authapp.domain.audit.entity.*;
import com.jaypal.authapp.service.oauth.OAuthLoginService;
import com.jaypal.authapp.dto.oauth.OAuthLoginResult;
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

        try {
            OAuth2AuthenticationToken oauthToken = validateAndExtractToken(authentication);
            OAuthLoginResult loginResult = oauthLoginService.login(oauthToken);

            validateLoginResult(loginResult);
            attachSecurityArtifacts(response, loginResult);

            auditSuccess(oauthToken, loginResult);

            String redirectUrl = getSuccessRedirectUrl();
            log.info("OAuth2 authentication successful - redirecting to: {}", redirectUrl);
            response.sendRedirect(redirectUrl);

        } catch (Exception ex) {
            log.error("OAuth2 success handler failed", ex);
            handleFailure(response, ex);
        }
    }

    /* ============================================================
       AUDIT
       ============================================================ */

    private void auditSuccess(
            OAuth2AuthenticationToken token,
            OAuthLoginResult result
    ) {
        try {
            UUID userId = Objects.requireNonNull(
                    result.userId(),
                    "OAuth login result missing userId"
            );

            AuthProvider provider = resolveProvider(token);

            auditService.record(
                    AuditCategory.AUTHENTICATION,
                    AuthAuditEvent.OAUTH_LOGIN,
                    AuditOutcome.SUCCESS,
                    AuditActor.userId(userId.toString()),       // ✅ ACTOR
                    AuditSubject.userId(userId.toString()),     // ✅ SUBJECT
                    null,
                    provider,
                    AuditContextHolder.getContext()
            );

        } catch (Exception ex) {
            log.error("Failed to audit OAuth success", ex);
        }
    }

    private AuthProvider resolveProvider(OAuth2AuthenticationToken token) {
        try {
            return AuthProvider.valueOf(
                    token.getAuthorizedClientRegistrationId().toUpperCase()
            );
        } catch (Exception ex) {
            return AuthProvider.SYSTEM;
        }
    }

    /* ============================================================
       VALIDATION
       ============================================================ */

    private OAuth2AuthenticationToken validateAndExtractToken(Authentication authentication) {
        Objects.requireNonNull(authentication, "Authentication cannot be null");

        if (!(authentication instanceof OAuth2AuthenticationToken token)) {
            throw new IllegalStateException(
                    "Expected OAuth2AuthenticationToken but got: "
                            + authentication.getClass().getSimpleName()
            );
        }

        if (token.getPrincipal() == null ||
                token.getPrincipal().getAttributes() == null ||
                token.getPrincipal().getAttributes().isEmpty()) {

            throw new IllegalStateException("OAuth2 principal attributes are missing");
        }

        return token;
    }

    private void validateLoginResult(OAuthLoginResult result) {
        Objects.requireNonNull(result, "OAuth login result cannot be null");
        Objects.requireNonNull(result.userId(), "OAuth login result missing userId");
        Objects.requireNonNull(result.accessToken(), "Access token cannot be null");
        Objects.requireNonNull(result.refreshToken(), "Refresh token cannot be null");

        if (result.accessToken().isBlank()) {
            throw new IllegalStateException("Access token is blank");
        }

        if (result.refreshToken().isBlank()) {
            throw new IllegalStateException("Refresh token is blank");
        }

        if (result.refreshTtlSeconds() <= 0) {
            throw new IllegalStateException(
                    "Invalid refresh token TTL: " + result.refreshTtlSeconds()
            );
        }
    }

    /* ============================================================
       RESPONSE
       ============================================================ */

    private void attachSecurityArtifacts(HttpServletResponse response, OAuthLoginResult result) {
        int refreshTtl = result.refreshTtlSeconds() > MAX_COOKIE_TTL
                ? Integer.MAX_VALUE
                : (int) result.refreshTtlSeconds();

        cookieService.attachRefreshCookie(response, result.refreshToken(), refreshTtl);
        cookieService.addNoStoreHeader(response);
    }

    private String getSuccessRedirectUrl() {
        String redirectUrl = frontendProperties.getSuccessRedirect();

        if (redirectUrl == null || redirectUrl.isBlank()) {
            throw new IllegalStateException(
                    "Frontend success redirect URL is not configured"
            );
        }

        return redirectUrl;
    }

    private void handleFailure(HttpServletResponse response, Exception ex) throws IOException {
        String failureUrl = frontendProperties.getFailureRedirect();

        if (failureUrl != null && !failureUrl.isBlank()) {
            response.sendRedirect(failureUrl);
        } else {
            response.sendError(
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "OAuth authentication processing failed"
            );
        }
    }
}
