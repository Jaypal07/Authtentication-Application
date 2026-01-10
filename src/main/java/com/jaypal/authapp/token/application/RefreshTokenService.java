package com.jaypal.authapp.token.application;

import com.jaypal.authapp.token.exception.RefreshTokenExpiredException;
import com.jaypal.authapp.token.exception.RefreshTokenNotFoundException;
import com.jaypal.authapp.token.model.RefreshToken;
import com.jaypal.authapp.token.repository.RefreshTokenRepository;
import jakarta.persistence.OptimisticLockException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    private final RefreshTokenRepository repository;
    private final RefreshTokenHasher tokenHasher;

    @Transactional
    public IssuedRefreshToken issue(UUID userId, long ttlSeconds) {

        String rawToken = RefreshTokenGenerator.generate();
        String tokenHash = tokenHasher.hash(rawToken);

        RefreshToken token = RefreshToken.issue(
                tokenHash,
                userId,
                Instant.now(),
                Instant.now().plusSeconds(ttlSeconds)
        );

        repository.save(token);

        return new IssuedRefreshToken(rawToken, token.getExpiresAt());
    }

    @Transactional
    public RefreshToken validate(String rawToken) {

        String tokenHash = tokenHasher.hash(rawToken);

        RefreshToken token = repository.findByTokenHash(tokenHash)
                .orElseThrow(RefreshTokenNotFoundException::new);

        if (!token.isActive(Instant.now())) {

            if (token.wasRotated()) {
                log.error(
                        "REFRESH TOKEN REUSE DETECTED userId={} replacedByHash={}",
                        token.getUserId(),
                        token.getReplacedByTokenHash()
                );
            }

            throw new RefreshTokenExpiredException();
        }

        return token;
    }


    @Transactional
    public IssuedRefreshToken rotate(
            RefreshToken current,
            long ttlSeconds
    ) {

        try {
            String nextRaw = RefreshTokenGenerator.generate();
            String nextHash = tokenHasher.hash(nextRaw);

            current.rotate(nextHash);
            repository.save(current);

            RefreshToken next = RefreshToken.issue(
                    nextHash,
                    current.getUserId(),
                    Instant.now(),
                    Instant.now().plusSeconds(ttlSeconds)
            );

            repository.save(next);

            return new IssuedRefreshToken(nextRaw, next.getExpiresAt());

        } catch (OptimisticLockException ex) {
            throw new RefreshTokenExpiredException();
        }
    }

    @Transactional
    public void revoke(String rawToken) {

        String tokenHash = tokenHasher.hash(rawToken);

        repository.findByTokenHash(tokenHash)
                .ifPresent(token -> {
                    if (token.isActive(Instant.now())) {
                        token.revoke();
                        repository.save(token);
                    }
                });
    }


    @Transactional
    public void revokeAllForUser(UUID userId) {

        for (RefreshToken token :
                repository.findAllByUserIdAndRevokedFalse(userId)) {

            if (token.isActive(Instant.now())) {
                token.revoke();
                repository.save(token);
            }
        }
    }
}
