package com.jaypal.authapp.token.application;

import com.jaypal.authapp.token.exception.RefreshTokenExpiredException;
import com.jaypal.authapp.token.exception.RefreshTokenNotFoundException;
import com.jaypal.authapp.token.exception.RefreshTokenRevokedException;
import com.jaypal.authapp.token.model.RefreshToken;
import com.jaypal.authapp.token.repository.RefreshTokenRepository;
import jakarta.persistence.OptimisticLockException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private static final int MAX_TOKENS_PER_USER = 10;
    private static final long CLEANUP_RETENTION_DAYS = 30L;

    private final RefreshTokenRepository repository;
    private final RefreshTokenHasher tokenHasher;

    @Transactional
    public IssuedRefreshToken issue(UUID userId, long ttlSeconds) {
        Objects.requireNonNull(userId, "User ID cannot be null");

        if (ttlSeconds <= 0) {
            throw new IllegalArgumentException("TTL must be positive");
        }

        final String rawToken = RefreshTokenGenerator.generate();
        final String tokenHash = tokenHasher.hash(rawToken);
        final Instant now = Instant.now();
        final Instant expiresAt = now.plusSeconds(ttlSeconds);

        final RefreshToken token = RefreshToken.issue(
                tokenHash,
                userId,
                now,
                expiresAt
        );

        try {
            repository.save(token);
            log.debug("Refresh token issued for user: {}", userId);
        } catch (DataIntegrityViolationException ex) {
            log.error("Token collision detected (extremely rare) - regenerating", ex);
            return issue(userId, ttlSeconds);
        }

        enforceTokenLimit(userId);

        return new IssuedRefreshToken(rawToken, token.getExpiresAt());
    }

    @Transactional(readOnly = true)
    public RefreshToken validate(String rawToken) {
        Objects.requireNonNull(rawToken, "Refresh token cannot be null");

        if (rawToken.isBlank()) {
            log.warn("Token validation failed: blank token");
            throw new RefreshTokenNotFoundException();
        }

        final String tokenHash = tokenHasher.hash(rawToken);
        final RefreshToken token = repository.findByTokenHash(tokenHash)
                .orElseThrow(() -> {
                    log.warn("Token validation failed: not found");
                    return new RefreshTokenNotFoundException();
                });

        final Instant now = Instant.now();

        if (token.isRevoked()) {
            if (token.wasRotated()) {
                log.error("SECURITY ALERT - Token reuse detected: userId={}, replacedBy={}",
                        token.getUserId(),
                        token.getReplacedByTokenHash());
                revokeTokenFamily(token);
            } else {
                log.warn("Token validation failed: explicitly revoked - userId={}", token.getUserId());
            }
            throw new RefreshTokenRevokedException();
        }

        if (token.isExpired(now)) {
            log.debug("Token validation failed: expired - userId={}", token.getUserId());
            throw new RefreshTokenExpiredException();
        }

        return token;
    }

    @Retryable(
            retryFor = {OptimisticLockException.class, ObjectOptimisticLockingFailureException.class},
            maxAttempts = 3,
            backoff = @Backoff(delay = 100, multiplier = 2)
    )
    @Transactional(isolation = Isolation.REPEATABLE_READ)
    public IssuedRefreshToken rotate(RefreshToken current, long ttlSeconds) {
        Objects.requireNonNull(current, "Current token cannot be null");

        if (ttlSeconds <= 0) {
            throw new IllegalArgumentException("TTL must be positive");
        }

        final String nextRaw = RefreshTokenGenerator.generate();
        final String nextHash = tokenHasher.hash(nextRaw);
        final Instant now = Instant.now();
        final Instant expiresAt = now.plusSeconds(ttlSeconds);

        current.rotate(nextHash);
        repository.save(current);

        final RefreshToken next = RefreshToken.issue(
                nextHash,
                current.getUserId(),
                now,
                expiresAt
        );

        repository.save(next);

        log.info("Token rotated successfully - userId={}", current.getUserId());

        return new IssuedRefreshToken(nextRaw, next.getExpiresAt());
    }

    @Transactional
    public void revoke(String rawToken) {
        Objects.requireNonNull(rawToken, "Refresh token cannot be null");

        if (rawToken.isBlank()) {
            log.debug("Revoke called with blank token - no action taken");
            return;
        }

        final String tokenHash = tokenHasher.hash(rawToken);

        repository.findByTokenHash(tokenHash).ifPresentOrElse(
                token -> {
                    if (token.isActive(Instant.now())) {
                        token.revoke();
                        repository.save(token);
                        log.info("Token revoked - userId={}", token.getUserId());
                    } else {
                        log.debug("Revoke called on inactive token - userId={}", token.getUserId());
                    }
                },
                () -> log.debug("Revoke called for non-existent token")
        );
    }

    @Transactional
    public void revokeAllForUser(UUID userId) {
        Objects.requireNonNull(userId, "User ID cannot be null");

        final Instant now = Instant.now();
        int revokedCount = 0;

        for (RefreshToken token : repository.findAllByUserIdAndRevokedFalse(userId)) {
            if (token.isActive(now)) {
                token.revoke();
                repository.save(token);
                revokedCount++;
            }
        }

        if (revokedCount > 0) {
            log.info("Revoked {} active tokens for user: {}", revokedCount, userId);
        } else {
            log.debug("No active tokens to revoke for user: {}", userId);
        }
    }

    @Scheduled(cron = "0 0 2 * * *")
    @Transactional
    public void cleanupExpiredTokens() {
        final Instant cutoff = Instant.now().minusSeconds(CLEANUP_RETENTION_DAYS * 86400L);

        try {
            final int deleted = repository.deleteByExpiresAtBefore(cutoff);

            if (deleted > 0) {
                log.info("Cleanup completed - removed {} expired tokens older than {} days",
                        deleted, CLEANUP_RETENTION_DAYS);
            }
        } catch (Exception ex) {
            log.error("Token cleanup job failed", ex);
        }
    }

    private void enforceTokenLimit(UUID userId) {
        final long activeCount = repository.countByUserIdAndRevokedFalse(userId);

        if (activeCount > MAX_TOKENS_PER_USER) {
            final int toRevoke = (int) (activeCount - MAX_TOKENS_PER_USER);

            repository.findOldestActiveTokensByUserId(userId, toRevoke)
                    .forEach(token -> {
                        token.revoke();
                        repository.save(token);
                    });

            log.info("Enforced token limit for user {} - revoked {} oldest tokens",
                    userId, toRevoke);
        }
    }

    private void revokeTokenFamily(RefreshToken compromisedToken) {
        final UUID userId = compromisedToken.getUserId();

        log.warn("Revoking entire token family for user {} due to reuse detection", userId);

        revokeAllForUser(userId);
    }
}

/*
CHANGELOG:
1. Added null checks for all method parameters
2. Added TTL validation (must be positive)
3. Added @Retryable for rotate() to handle optimistic lock failures
4. Added REPEATABLE_READ isolation level for rotate()
5. Added token limit enforcement (max 10 active tokens per user)
6. Added scheduled cleanup job for expired tokens (runs daily at 2 AM)
7. Added token reuse detection with automatic family revocation
8. Added comprehensive logging for security audit trail
9. Added DataIntegrityViolationException handling for hash collisions
10. Separated revoked vs expired states in validation
11. Added counter for revoked tokens in revokeAllForUser
12. Made validation read-only transaction
13. Added revokeTokenFamily method for security incident response
14. Used ifPresentOrElse for clearer intent in revoke()
*/