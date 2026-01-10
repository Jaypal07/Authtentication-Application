package com.jaypal.authapp.audit.resolver;

import com.jaypal.authapp.auth.dto.AuthLoginResult;
import com.jaypal.authapp.auth.dto.TokenResponse;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class IdentityResolver {

    public UUID fromSecurityContext() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) return null;
        if (auth.getPrincipal() instanceof AuthPrincipal p) return p.getUserId();
        return null;
    }

    public UUID fromResult(Object result) {
        if (result instanceof ResponseEntity<?> r && r.getBody() instanceof TokenResponse tr)
            return tr.user().id();
        if (result instanceof AuthLoginResult ar)
            return ar.user().getId();
        return null;
    }
}

