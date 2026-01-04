package com.jaypal.authapp.token.repository;

import com.jaypal.authapp.token.model.RefreshToken;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository
        extends JpaRepository<RefreshToken, UUID> {

    // ---------- REFRESH FLOW (SAFE, IDENTITY ONLY) ----------

    @Query("""
        select rt
        from RefreshToken rt
        join fetch rt.user u
        where rt.jti = :jti
    """)
    Optional<RefreshToken> findForRefresh(
            @Param("jti") String jti
    );

    // ---------- LOGOUT / SINGLE SESSION ----------

    Optional<RefreshToken> findByJtiAndUserId(
            String jti,
            UUID userId
    );

    // ---------- ADMIN / SECURITY ----------

    @Modifying
    @Query("""
        update RefreshToken rt
        set rt.revoked = true,
            rt.revokedAt = CURRENT_TIMESTAMP
        where rt.user.id = :userId
          and rt.revoked = false
    """)
    int revokeAllActiveByUserId(
            @Param("userId") UUID userId
    );
}
