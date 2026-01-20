package com.jaypal.authapp.domain.audit.entity;

public record AuditActor(
        AuditSubjectType type,
        String identifier
) {

    public static AuditActor system() {
        return new AuditActor(AuditSubjectType.SYSTEM, "SYSTEM");
    }

    public static AuditActor userId(String userId) {
        return new AuditActor(AuditSubjectType.USER_ID, userId);
    }

    public static AuditActor anonymous() {
        return new AuditActor(AuditSubjectType.ANONYMOUS, null);
    }
}
