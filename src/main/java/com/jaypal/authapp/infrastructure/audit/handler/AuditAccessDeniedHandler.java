package com.jaypal.authapp.infrastructure.audit.handler;

import com.jaypal.authapp.infrastructure.audit.context.AuditContextHolder;
import com.jaypal.authapp.domain.audit.entity.*;
import com.jaypal.authapp.domain.audit.service.AuthAuditService;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

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

        // ✅ Determine the subject (who the action is performed on)
        AuditSubject subject = resolveSubject();

        // ✅ Determine the actor (who triggered the action)
        AuditActor actor = resolveActor();

        auditService.record(
                AuditCategory.AUTHORIZATION,
                AuthAuditEvent.ACCESS_DENIED,
                AuditOutcome.FAILURE,
                actor,        // actor triggering the event
                subject,      // subject affected
                AuthFailureReason.ACCESS_DENIED,
                AuthProvider.SYSTEM,
                AuditContextHolder.getContext()
        );

        log.warn(
                "ACCESS DENIED | actor={} subject={} uri={} method={}",
                actor.type() == AuditSubjectType.USER_ID ? actor.identifier() : actor.type(),
                subject.getType() == AuditSubjectType.USER_ID ? subject.getIdentifier() : subject.getType(),
                request.getRequestURI(),
                request.getMethod()
        );
    }

    /** Resolve the subject (the user who attempted the action) */
    private AuditSubject resolveSubject() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();

            if (auth == null || !auth.isAuthenticated()) {
                return AuditSubject.anonymous();
            }

            Object principal = auth.getPrincipal();

            if (principal instanceof String p && "anonymousUser".equalsIgnoreCase(p)) {
                return AuditSubject.anonymous();
            }

            if (principal instanceof AuthPrincipal authPrincipal) {
                return AuditSubject.userId(authPrincipal.getUserId().toString());
            }

            log.warn("Unhandled principal type for ACCESS_DENIED audit: {}", principal.getClass().getName());
            return AuditSubject.anonymous();

        } catch (Exception ex) {
            log.warn("Failed to resolve subject for ACCESS_DENIED", ex);
            return AuditSubject.anonymous();
        }
    }

    /** Resolve the actor (the real initiator of the action) */
    private AuditActor resolveActor() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();

            if (auth == null || !auth.isAuthenticated()) {
                return AuditActor.system(); // SYSTEM triggered
            }

            Object principal = auth.getPrincipal();

            if (principal instanceof AuthPrincipal authPrincipal) {
                return AuditActor.userId(authPrincipal.getUserId().toString()); // real user triggered
            }

            return AuditActor.system();

        } catch (Exception ex) {
            log.warn("Failed to resolve actor for ACCESS_DENIED", ex);
            return AuditActor.system();
        }
    }
}
