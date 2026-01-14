package com.jaypal.authapp.security.ratelimit;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class InvalidRefreshTokenRateLimiter {

    private static final int MAX_ATTEMPTS = 10;
    private static final long WINDOW_SECONDS = 60;

    private final Map<String, Attempt> attempts = new ConcurrentHashMap<>();

    public void check(String ip) {
        if (ip == null || ip.isBlank()) {
            return;
        }

        long now = Instant.now().getEpochSecond();

        Attempt attempt = attempts.compute(ip, (k, existing) -> {
            if (existing == null || now - existing.firstAttempt > WINDOW_SECONDS) {
                return new Attempt(1, now);
            }
            existing.count++;
            return existing;
        });

        if (attempt.count > MAX_ATTEMPTS) {
            throw new RateLimitExceededException();
        }
    }

    private static final class Attempt {
        int count;
        long firstAttempt;

        Attempt(int count, long firstAttempt) {
            this.count = count;
            this.firstAttempt = firstAttempt;
        }
    }
}
