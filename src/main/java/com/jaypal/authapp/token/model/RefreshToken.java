package com.jaypal.authapp.token.model;

import jakarta.persistence.*;
import lombok.Getter;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Getter
@Entity
@Table(
        name = "refresh_tokens",
        indexes = {
                @Index(name = "idx_refresh_token_hash", columnList = "token_hash", unique = true),
                @Index(name = "idx_refresh_tokens_user_id", columnList = "user_id"),
                @Index(name = "idx_refresh_tokens_user_revoked", columnList = "user_id, revoked"),
                @Index(name = "idx_refresh_tokens_expires_at", columnList = "expires_at")
        }
)
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Version
    private Long version;

    @Column(name = "token_hash", nullable = false, updatable = false, length = 64)
    private String tokenHash;

    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID userId;

    @Column(nullable = false, updatable = false)
    private Instant issuedAt;

    @Column(nullable = false, updatable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private boolean revoked = false;

    @Column
    private Instant revokedAt;

    @Column(name = "replaced_by_token_hash", length = 64)
    private String replacedByTokenHash;

    protected RefreshToken() {}

    private RefreshToken(
            String tokenHash,
            UUID userId,
            Instant issuedAt,
            Instant expiresAt
    ) {
        this.tokenHash = requireNonBlank(tokenHash, "tokenHash");
        this.userId = Objects.requireNonNull(userId, "userId cannot be null");
        this.issuedAt = Objects.requireNonNull(issuedAt, "issuedAt cannot be null");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt cannot be null");
        this.revoked = false;
    }

    public static RefreshToken issue(
            String tokenHash,
            UUID userId,
            Instant issuedAt,
            Instant expiresAt
    ) {
        if (expiresAt.isBefore(issuedAt) || expiresAt.equals(issuedAt)) {
            throw new IllegalArgumentException(
                    String.format("expiresAt (%s) must be after issuedAt (%s)", expiresAt, issuedAt)
            );
        }
        return new RefreshToken(tokenHash, userId, issuedAt, expiresAt);
    }

    public void revoke() {
        ensureActive();
        this.revoked = true;
        this.revokedAt = Instant.now();
    }

    public void rotate(String newTokenHash) {
        ensureActive();
        this.revoked = true;
        this.revokedAt = Instant.now();
        this.replacedByTokenHash = requireNonBlank(newTokenHash, "newTokenHash");
    }

    public boolean isExpired(Instant now) {
        Objects.requireNonNull(now, "now cannot be null");
        return now.isAfter(expiresAt) || now.equals(expiresAt);
    }

    public boolean isActive(Instant now) {
        Objects.requireNonNull(now, "now cannot be null");
        return !revoked && !isExpired(now);
    }

    public boolean isRevoked() {
        return revoked;
    }

    public boolean wasRotated() {
        return replacedByTokenHash != null && !replacedByTokenHash.isBlank();
    }

    private void ensureActive() {
        if (revoked) {
            throw new IllegalStateException("Refresh token already revoked");
        }

        final Instant now = Instant.now();
        if (isExpired(now)) {
            throw new IllegalStateException(
                    String.format("Refresh token expired at %s (current time: %s)", expiresAt, now)
            );
        }
    }

    private static String requireNonBlank(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " cannot be null or blank");
        }
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RefreshToken that)) return false;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}

/*
CHANGELOG:
1. Changed version type from long to Long for better JPA null handling
2. Added composite index (user_id, revoked) for efficient active token queries
3. Added expires_at index for cleanup job performance
4. Added equals check to isExpired (edge case: now == expiresAt)
5. Added null check in isExpired and isActive methods
6. Added explicit isRevoked() getter for clarity
7. Made wasRotated check for blank string too
8. Added default value for revoked field (false)
9. Improved error messages in ensureActive with timestamps
10. Added equals() and hashCode() based on ID
11. Improved validation error messages with actual values
*/