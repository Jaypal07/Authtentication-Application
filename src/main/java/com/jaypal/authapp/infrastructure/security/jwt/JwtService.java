package com.jaypal.authapp.infrastructure.security.jwt;

import com.jaypal.authapp.domain.user.entity.PermissionType;
import com.jaypal.authapp.domain.user.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@Getter
public class JwtService {

    private static final int MINIMUM_SECRET_LENGTH = 64;

    private static final String CLAIM_TYPE = "typ";
    private static final String CLAIM_EMAIL = "email";
    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_PERMS = "perms";
    private static final String CLAIM_PV = "pv";

    private final String rawSecret;
    private final long accessTtlSeconds;
    private final long refreshTtlSeconds;
    private final String issuer;

    private SecretKey secretKey;

    public JwtService(
            @Value("${security.jwt.secret}") String secret,
            @Value("${security.jwt.access-ttl-seconds}") long accessTtlSeconds,
            @Value("${security.jwt.refresh-ttl-seconds}") long refreshTtlSeconds,
            @Value("${security.jwt.issuer}") String issuer
    ) {
        this.rawSecret = secret;
        this.accessTtlSeconds = accessTtlSeconds;
        this.refreshTtlSeconds = refreshTtlSeconds;
        this.issuer = issuer;
    }

    @PostConstruct
    public void init() {
        validateConfiguration();
        this.secretKey = JwtUtils.createKey(rawSecret);
        log.info(
                "JWT Service initialized - Access TTL: {}s, Refresh TTL: {}s, Issuer: {}",
                accessTtlSeconds, refreshTtlSeconds, issuer
        );
    }

    private void validateConfiguration() {
        requireNonBlank(rawSecret, "JWT secret");
        requirePositive(accessTtlSeconds, "Access TTL");
        requirePositive(refreshTtlSeconds, "Refresh TTL");
        requireNonBlank(issuer, "JWT issuer");

        if (rawSecret.length() < MINIMUM_SECRET_LENGTH) {
            throw new IllegalStateException(
                    "JWT secret must be at least " + MINIMUM_SECRET_LENGTH + " characters"
            );
        }

        if (refreshTtlSeconds < accessTtlSeconds) {
            throw new IllegalStateException("Refresh TTL must be >= access TTL");
        }
    }

    public String generateAccessToken(User user, Set<PermissionType> permissions) {
        Objects.requireNonNull(user, "User cannot be null");
        Objects.requireNonNull(user.getId(), "User ID cannot be null");
        Objects.requireNonNull(user.getEmail(), "User email cannot be null");
        Objects.requireNonNull(permissions, "Permissions cannot be null");

        final Map<String, Object> claims = Map.of(
                CLAIM_TYPE, TokenType.ACCESS.name().toLowerCase(),
                CLAIM_EMAIL, user.getEmail(),
                CLAIM_ROLES, new ArrayList<>(user.getRoles()),
                CLAIM_PERMS, permissions.stream().map(Enum::name).toList(),
                CLAIM_PV, user.getPermissionVersion()
        );

        return JwtUtils.buildAccessToken(
                secretKey,
                issuer,
                user.getId(),
                claims,
                accessTtlSeconds
        );
    }

    public Jws<Claims> parseAccessToken(String token) {
        final Jws<Claims> parsed = JwtUtils.parse(secretKey, issuer, token);
        final String type = parsed.getBody().get(CLAIM_TYPE, String.class);

        if (TokenType.from(type) != TokenType.ACCESS) {
            throw new IllegalArgumentException("Token is not an access token");
        }

        return parsed;
    }

    public UUID extractUserId(Claims claims) {
        return UUID.fromString(requireNonBlank(claims.getSubject(), "Token subject"));
    }

    public long extractPermissionVersion(Claims claims) {
        final Long pv = claims.get(CLAIM_PV, Long.class);
        if (pv == null) {
            throw new IllegalArgumentException("Permission version missing from token");
        }
        return pv;
    }

    public Set<String> extractRoles(Claims claims) {
        return extractStringSet(claims, CLAIM_ROLES);
    }

    public Set<String> extractPermissions(Claims claims) {
        return extractStringSet(claims, CLAIM_PERMS);
    }

    public String extractEmail(Claims claims) {
        return requireNonBlank(claims.get(CLAIM_EMAIL, String.class), "Email");
    }

    private Set<String> extractStringSet(Claims claims, String key) {
        final Object raw = claims.get(key);
        if (raw == null) return Set.of();

        if (!(raw instanceof List<?> list)) {
            throw new IllegalStateException("Claim '" + key + "' is not a list");
        }

        return list.stream()
                .map(String.class::cast)
                .collect(Collectors.toUnmodifiableSet());
    }

    private static void requirePositive(long value, String name) {
        if (value <= 0) throw new IllegalStateException(name + " must be positive");
    }

    private static String requireNonBlank(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " cannot be null or empty");
        }
        return value;
    }
}
