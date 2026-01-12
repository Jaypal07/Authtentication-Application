package com.jaypal.authapp.audit.context;

import com.jaypal.authapp.audit.application.AuditRequestContext;
import org.springframework.core.task.TaskDecorator;
import org.springframework.lang.NonNull;

public final class AuditContextHolder {

    private static final ThreadLocal<AuditRequestContext> CONTEXT = new ThreadLocal<>();

    private AuditContextHolder() {
        throw new UnsupportedOperationException("Utility class");
    }

    public static void setContext(AuditRequestContext context) {
        CONTEXT.set(context);
    }

    public static AuditRequestContext getContext() {
        return CONTEXT.get();
    }

    public static void clear() {
        CONTEXT.remove();
    }

    public static class ContextCopyingDecorator implements TaskDecorator {
        @Override
        @NonNull
        public Runnable decorate(@NonNull Runnable task) {
            final AuditRequestContext context = AuditContextHolder.getContext();

            return () -> {
                try {
                    AuditContextHolder.setContext(context);
                    task.run();
                } finally {
                    AuditContextHolder.clear();
                }
            };
        }
    }
}

/*
CHANGELOG:
1. Created ThreadLocal holder for audit request context
2. Added ContextCopyingDecorator to propagate context to async threads
3. Ensures context is cleared after async task completion
4. Private constructor to prevent instantiation
5. This solves the async context propagation problem
*/