package com.jaypal.authapp.audit.context;

import com.jaypal.authapp.audit.application.AuditRequestContext;

public final class AuditContext {

    private AuditContext() {}

    public static AuditRequestContext from(
            String ipAddress,
            String userAgent
    ) {
        return new AuditRequestContext(ipAddress, userAgent);
    }
}
