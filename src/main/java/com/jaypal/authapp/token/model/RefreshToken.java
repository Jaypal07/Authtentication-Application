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
                @Index(name = "idx_refresh_tokens_user_id", columnList = "user_id")
        }
)
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Version
    private long version;

    @Column(name = "token_hash", nullable = false, updatable = false, length = 64)
    private String tokenHash;

    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID userId;

    @Column(nullable = false, updatable = false)
    private Instant issuedAt;

    @Column(nullable = false, updatable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private boolean revoked;

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
        this.userId = Objects.requireNonNull(userId, "userId");
        this.issuedAt = Objects.requireNonNull(issuedAt, "issuedAt");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
        this.revoked = false;
    }

    public static RefreshToken issue(
            String tokenHash,
            UUID userId,
            Instant issuedAt,
            Instant expiresAt
    ) {
        if (expiresAt.isBefore(issuedAt)) {
            throw new IllegalArgumentException("expiresAt must be after issuedAt");
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
        this.replacedByTokenHash =
                requireNonBlank(newTokenHash, "newTokenHash");
    }

    public boolean isExpired(Instant now) {
        return now.isAfter(expiresAt);
    }

    public boolean isActive(Instant now) {
        return !revoked && !isExpired(now);
    }

    public boolean wasRotated() {
        return replacedByTokenHash != null;
    }

    public String getReplacedByTokenHash() {
        return replacedByTokenHash;
    }

    public UUID getUserId() {
        return userId;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    private void ensureActive() {
        if (revoked) {
            throw new IllegalStateException("Refresh token already revoked");
        }
        if (isExpired(Instant.now())) {
            throw new IllegalStateException("Refresh token expired");
        }
    }

    private static String requireNonBlank(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}
