package com.jaypal.authapp.token.repository;

import com.jaypal.authapp.token.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository
        extends JpaRepository<RefreshToken, UUID> {

    /**
     * Used during refresh flow.
     * Token is looked up by hash, never raw value.
     */
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /**
     * Used for logout / explicit revoke of a single session.
     * Hash + userId prevents cross-user abuse.
     */
    Optional<RefreshToken> findByTokenHashAndUserId(
            String tokenHash,
            UUID userId
    );

    /**
     * Used for admin or global logout.
     * Tokens are loaded and revoked individually
     * to enforce invariants and optimistic locking.
     */
    Iterable<RefreshToken> findAllByUserIdAndRevokedFalse(
            UUID userId
    );
}
