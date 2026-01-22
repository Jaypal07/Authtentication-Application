package com.jaypal.authapp.infrastructure.audit.context;

import com.jaypal.authapp.domain.audit.entity.AuthFailureReason;
import com.jaypal.authapp.dto.audit.AuditRequestContext;
import org.springframework.core.task.TaskDecorator;
import org.springframework.lang.NonNull;

public final class AuditContextHolder {

    private static final ThreadLocal<AuditRequestContext> CONTEXT = new ThreadLocal<>();

    private static final ThreadLocal<Boolean> NO_OP = ThreadLocal.withInitial(() -> false);

    private static final ThreadLocal<Boolean> FAILURE = ThreadLocal.withInitial(() -> false);

    private static final ThreadLocal<AuthFailureReason> FAILURE_REASON = new ThreadLocal<>();

    private AuditContextHolder() {
        throw new UnsupportedOperationException("Utility class");
    }

    /* ===================== Context ===================== */

    public static void setContext(AuditRequestContext context) {
        if (context == null) {
            CONTEXT.remove();
        } else {
            CONTEXT.set(context);
        }
    }

    public static AuditRequestContext getContext() {
        return CONTEXT.get();
    }

    /* ===================== Outcome APIs ===================== */

    public static void markNoOp() {
        NO_OP.set(true);
    }

    public static boolean isNoOp() {
        return Boolean.TRUE.equals(NO_OP.get());
    }

    public static void markFailure(@NonNull AuthFailureReason reason) {
        FAILURE.set(true);
        FAILURE_REASON.set(reason);
        NO_OP.remove(); // ensure NO_OP never wins over FAILURE
    }

    public static boolean isFailure() {
        return Boolean.TRUE.equals(FAILURE.get());
    }

    public static AuthFailureReason getFailureReason() {
        return FAILURE_REASON.get();
    }

    public static void markSuccess() {
        NO_OP.remove();
        FAILURE.remove();
        FAILURE_REASON.remove();
    }

    /* ===================== Cleanup ===================== */

    public static void clear() {
        CONTEXT.remove();
        NO_OP.remove();
        FAILURE.remove();
        FAILURE_REASON.remove();
    }

    /* ===================== Async propagation ===================== */

    public static class ContextCopyingDecorator implements TaskDecorator {

        @Override
        @NonNull
        public Runnable decorate(@NonNull Runnable task) {
            final AuditRequestContext context = getContext();
            final boolean noOp = isNoOp();
            final boolean failure = isFailure();
            final AuthFailureReason failureReason = getFailureReason();

            return () -> {
                try {
                    setContext(context);
                    if (noOp) markNoOp();
                    if (failure) markFailure(failureReason);
                    task.run();
                } finally {
                    clear();
                }
            };
        }
    }
}
