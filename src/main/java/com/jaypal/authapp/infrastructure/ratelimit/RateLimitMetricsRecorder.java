package com.jaypal.authapp.infrastructure.ratelimit;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class RateLimitMetricsRecorder {

    private final MeterRegistry meterRegistry;

    public void recordReset(String type) {
        Counter.builder("auth.ratelimit.reset")
                .tag("type", type)
                .register(meterRegistry)
                .increment();
    }

    public void recordAllowed(RateLimitContext ctx) {
        buildRequestCounter("allowed", ctx).increment();
    }

    public void recordBlocked(RateLimitContext ctx) {
        buildRequestCounter("blocked", ctx).increment();
    }

    public void recordFailOpen(RateLimitContext ctx) {
        Counter.builder("auth.ratelimit.fail_open")
                .tag("endpoint", ctx.endpoint())
                .tag("method", ctx.method())
                .tag("scope", ctx.scope())
                .register(meterRegistry)
                .increment();
    }

    private Counter buildRequestCounter(String result, RateLimitContext ctx) {
        return Counter.builder("auth.ratelimit.requests")
                .tag("result", result)
                .tag("endpoint", ctx.endpoint())
                .tag("method", ctx.method())
                .tag("scope", ctx.scope())
                .register(meterRegistry);
    }
}