package com.jaypal.authapp.audit.application;

import com.jaypal.authapp.audit.domain.AuthAuditEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicLong;

@Component
@Slf4j
public class AuditFailureMonitor {

    private final AtomicLong failureCount = new AtomicLong();

    public void onAuditFailure(AuthAuditEvent event, Exception ex) {
        long count = failureCount.incrementAndGet();
        log.error("AUDIT_WRITE_FAILURE count={} event={}", count, event, ex);
    }

    public long getFailureCount() {
        return failureCount.get();
    }
}
