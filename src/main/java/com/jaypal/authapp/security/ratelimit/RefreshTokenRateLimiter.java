package com.jaypal.authapp.security.ratelimit;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RefreshTokenRateLimiter {

    private static final int MAX_ATTEMPTS = 5;
    private static final long WINDOW_SECONDS = 60;

    private final Map<UUID, Attempt> attempts = new ConcurrentHashMap<>();

    public void check(UUID userId) {
        if (userId == null) {
            throw new IllegalArgumentException("UserId must not be null");
        }

        long now = Instant.now().getEpochSecond();

        Attempt attempt = attempts.compute(userId, (id, existing) -> {
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

    public void reset(UUID userId) {
        if (userId != null) {
            attempts.remove(userId);
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
