package com.jaypal.authapp.audit.annotation;

import com.jaypal.authapp.audit.domain.AuthAuditEvent;
import com.jaypal.authapp.audit.domain.AuditSubjectType;
import com.jaypal.authapp.audit.domain.AuthProvider;

import java.lang.annotation.*;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AuthAudit {

    AuthAuditEvent event();

    AuditSubjectType subject();

    AuthProvider provider() default AuthProvider.LOCAL;
}

