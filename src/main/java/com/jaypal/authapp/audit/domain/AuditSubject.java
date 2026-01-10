package com.jaypal.authapp.audit.domain;

import java.util.Objects;

public final class AuditSubject {

    private final AuditSubjectType type;
    private final String identifier;

    private AuditSubject(AuditSubjectType type, String identifier) {
        this.type = Objects.requireNonNull(type, "subject type must not be null");
        this.identifier = identifier;
    }

    public static AuditSubject anonymous() {
        return new AuditSubject(AuditSubjectType.ANONYMOUS, null);
    }

    public static AuditSubject system() {
        return new AuditSubject(AuditSubjectType.SYSTEM, "SYSTEM");
    }

    public static AuditSubject userId(String userId) {
        if (userId == null || userId.isBlank()) {
            throw new IllegalArgumentException("userId must not be blank");
        }
        return new AuditSubject(AuditSubjectType.USER_ID, userId);
    }

    public static AuditSubject email(String emailHashOrEncrypted) {
        if (emailHashOrEncrypted == null || emailHashOrEncrypted.isBlank()) {
            throw new IllegalArgumentException("email identifier must not be blank");
        }
        return new AuditSubject(AuditSubjectType.EMAIL, emailHashOrEncrypted);
    }

    public AuditSubjectType getType() {
        return type;
    }

    public String getIdentifier() {
        return identifier;
    }
}
