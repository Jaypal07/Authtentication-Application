package com.jaypal.authapp.audit.application;

import com.jaypal.authapp.audit.context.AuditContextHolder;
import com.jaypal.authapp.audit.domain.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuditAccessDeniedHandler implements AccessDeniedHandler {

    private final AuthAuditService auditService;

    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            AccessDeniedException ex
    ) {

        auditService.record(
                AuditCategory.AUTHORIZATION,
                AuthAuditEvent.ACCESS_DENIED,
                AuditOutcome.FAILURE,
                AuditSubject.anonymous(),
                AuthFailureReason.ACCESS_DENIED,
                AuthProvider.SYSTEM,
                AuditContextHolder.getContext()
        );

        log.warn("ACCESS DENIED | uri={} method={}",
                request.getRequestURI(),
                request.getMethod()
        );
    }
}

