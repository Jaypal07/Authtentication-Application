package com.jaypal.authapp.audit.context;

import java.util.UUID;

public final class AuditContext {

    private static final ThreadLocal<String> EMAIL = new ThreadLocal<>();
    private static final ThreadLocal<UUID> USER_ID = new ThreadLocal<>();

    private AuditContext() {}

    public static void setEmail(String email) {
        EMAIL.set(email);
    }

    public static String getEmail() {
        return EMAIL.get();
    }

    public static void setUserId(UUID userId) {
        USER_ID.set(userId);
    }

    public static UUID getUserId() {
        return USER_ID.get();
    }

    public static void clear() {
        EMAIL.remove();
        USER_ID.remove();
    }

}
