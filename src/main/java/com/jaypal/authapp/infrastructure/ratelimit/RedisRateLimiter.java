package com.jaypal.authapp.infrastructure.ratelimit;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
public class RedisRateLimiter {

    private final StringRedisTemplate redisTemplate;
    private final MeterRegistry meterRegistry;
    private DefaultRedisScript<Long> script;

    public RedisRateLimiter(@NonNull StringRedisTemplate redisTemplate,
                            @NonNull MeterRegistry meterRegistry) {
        this.redisTemplate = redisTemplate;
        this.meterRegistry = meterRegistry;
    }

    /**
     * Production-safe initialization.
     * Loads Lua script and validates it against Redis.
     * Failures are logged, but will not stop app startup.
     */
    @PostConstruct
    void init() {
        this.script = new DefaultRedisScript<>();
        this.script.setLocation(new ClassPathResource("ratelimit/TokenBucket.lua"));
        this.script.setResultType(Long.class);

        try {
            // optional lightweight test, fail-safe
            redisTemplate.execute(script,
                    List.of("rl:health"),
                    "1", "1", String.valueOf(Instant.now().getEpochSecond())
            );
            log.info("Redis rate limit Lua script validated successfully");
        } catch (Exception ex) {
            log.error(
                    "Redis not ready during startup. Rate limiter will fail-open until Redis is available",
                    ex
            );
        }
    }

    /**
     * Evaluates if a request should be allowed.
     * Implements fail-open strategy on Redis errors.
     */
    public boolean allow(@NonNull String key,
                         int capacity,
                         double refillPerSecond,
                         @NonNull RateLimitContext ctx) {

        long startNs = System.nanoTime();

        try {
            Long result = redisTemplate.execute(
                    script,
                    List.of(key),
                    String.valueOf(capacity),
                    String.valueOf(refillPerSecond),
                    String.valueOf(Instant.now().getEpochSecond())
            );

            boolean allowed = result != null && result == 1;

            recordDecision(allowed, ctx);
            recordLatency(startNs, ctx);
            logRateLimitDecision(allowed, key, ctx, capacity, refillPerSecond);

            return allowed;

        } catch (Exception ex) {
            recordFailOpen(ctx);
            recordLatency(startNs, ctx);

            log.error(
                    "Redis rate limiter failure. Failing open | key={} endpoint={} scope={}",
                    key, ctx.endpoint(), ctx.scope(), ex
            );
            return true; // fail-open
        }
    }

    /* =========================
       METRICS & LOGGING HELPERS
       ========================= */

    private void recordDecision(boolean allowed, RateLimitContext ctx) {
        Counter.builder("auth.ratelimit.requests")
                .tag("result", allowed ? "allowed" : "blocked")
                .tag("endpoint", ctx.endpoint())
                .tag("method", ctx.method())
                .tag("scope", ctx.scope())
                .register(meterRegistry)
                .increment();
    }

    private void recordFailOpen(RateLimitContext ctx) {
        Counter.builder("auth.ratelimit.fail_open")
                .tag("endpoint", ctx.endpoint())
                .tag("method", ctx.method())
                .tag("scope", ctx.scope())
                .register(meterRegistry)
                .increment();
    }

    private void recordLatency(long startNs, RateLimitContext ctx) {
        Timer.builder("auth.ratelimit.redis.latency")
                .description("Redis rate limiter execution latency")
                .tag("endpoint", ctx.endpoint())
                .tag("method", ctx.method())
                .tag("scope", ctx.scope())
                .register(meterRegistry)
                .record(System.nanoTime() - startNs, TimeUnit.NANOSECONDS);
    }

    private void logRateLimitDecision(boolean allowed,
                                      String key,
                                      RateLimitContext ctx,
                                      int capacity,
                                      double refillPerSecond) {
        if (allowed) {
            log.debug(
                    "Rate limit allowed | key={} endpoint={} scope={}",
                    key, ctx.endpoint(), ctx.scope()
            );
        } else {
            log.warn(
                    "Rate limit blocked | key={} endpoint={} scope={} capacity={} refillPerSecond={}",
                    key, ctx.endpoint(), ctx.scope(), capacity, refillPerSecond
            );
        }
    }
}
