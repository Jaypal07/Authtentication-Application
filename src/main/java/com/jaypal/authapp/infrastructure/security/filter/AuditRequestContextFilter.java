package com.jaypal.authapp.infrastructure.security.filter;

import com.jaypal.authapp.dto.audit.AuditRequestContext;
import com.jaypal.authapp.infrastructure.audit.context.AuditContextHolder;
import com.jaypal.authapp.infrastructure.audit.context.IpAddressExtractor;
import com.jaypal.authapp.infrastructure.audit.context.UserAgentExtractor;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Refactored filter with improved separation of concerns.
 * Delegates extraction to specialized components.
 */
@Slf4j
@Component
public class AuditRequestContextFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain chain
    ) throws ServletException, IOException {

        try {
            initializeAuditContext(request);
            enrichContextWithUserId();
            logContextInitialization(request);

            chain.doFilter(request, response);

        } finally {
            AuditContextHolder.clear();
        }
    }

    private void initializeAuditContext(HttpServletRequest request) {
        String ipAddress = IpAddressExtractor.extract(request);
        String userAgent = UserAgentExtractor.extract(request);

        AuditContextHolder.setContext(
                new AuditRequestContext(ipAddress, userAgent, null)
        );
    }

    private void enrichContextWithUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (isAuthenticatedUser(authentication)) {
            AuthPrincipal principal = (AuthPrincipal) authentication.getPrincipal();
            updateContextWithUserId(principal.getUserId().toString());

            log.trace("Audit userId set from SecurityContext: {}", principal.getUserId());
        }
    }

    private boolean isAuthenticatedUser(Authentication authentication) {
        return authentication != null &&
                authentication.isAuthenticated() &&
                authentication.getPrincipal() instanceof AuthPrincipal;
    }

    private void updateContextWithUserId(String userId) {
        AuditRequestContext currentContext = AuditContextHolder.getContext();

        AuditContextHolder.setContext(
                new AuditRequestContext(
                        currentContext.ipAddress(),
                        currentContext.userAgent(),
                        userId
                )
        );
    }

    private void logContextInitialization(HttpServletRequest request) {
        if (log.isTraceEnabled()) {
            AuditRequestContext context = AuditContextHolder.getContext();
            log.trace(
                    "Audit context initialized: ip={}, ua={}",
                    maskIp(context.ipAddress()),
                    maskUserAgent(context.userAgent())
            );
        }
    }

    private String maskIp(String ip) {
        if (ip == null || "unknown".equals(ip)) {
            return "unknown";
        }

        if (ip.contains(":")) { // IPv6
            return "***:***";
        }

        int lastDot = ip.lastIndexOf('.');
        return lastDot > 0 ? ip.substring(0, lastDot) + ".***" : "***";
    }

    private String maskUserAgent(String ua) {
        if (ua == null || ua.length() <= 20) {
            return "***";
        }
        return ua.substring(0, 20) + "...";
    }
}