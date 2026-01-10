package com.jaypal.authapp.security.jwt;

import com.jaypal.authapp.user.model.PermissionType;
import com.jaypal.authapp.user.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Getter
public class JwtService {

    private static final String CLAIM_TYPE = "typ";
    private static final String CLAIM_EMAIL = "email";
    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_PERMS = "perms";
    private static final String CLAIM_PV = "pv";

    private final SecretKey secretKey;
    private final long accessTtlSeconds;
    private final String issuer;

    public JwtService(
            @Value("${security.jwt.secret}") String secret,
            @Value("${security.jwt.access-ttl-seconds}") long accessTtlSeconds,
            @Value("${security.jwt.issuer}") String issuer
    ) {
        if (secret == null || secret.length() < 64) {
            throw new IllegalArgumentException("JWT secret too weak");
        }
        this.secretKey = JwtUtils.createKey(secret);
        this.accessTtlSeconds = accessTtlSeconds;
        this.issuer = issuer;
    }

    public String generateAccessToken(User user, Set<PermissionType> permissions) {

        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_TYPE, TokenType.ACCESS.name().toLowerCase());
        claims.put(CLAIM_EMAIL, user.getEmail());
        claims.put(CLAIM_ROLES, new ArrayList<>(user.getRoles()));
        claims.put(
                CLAIM_PERMS,
                permissions.stream().map(Enum::name).toList()
        );
        claims.put(CLAIM_PV, user.getPermissionVersion());

        return JwtUtils.buildAccessToken(
                secretKey,
                issuer,
                user.getId(),
                claims,
                accessTtlSeconds
        );
    }

    public Jws<Claims> parseAccessToken(String token) {
        Jws<Claims> parsed = JwtUtils.parse(secretKey, issuer, token);

        String type = parsed.getBody().get(CLAIM_TYPE, String.class);
        if (TokenType.from(type) != TokenType.ACCESS) {
            throw new IllegalArgumentException("Not an access token");
        }

        return parsed;
    }

    public UUID extractUserId(Claims claims) {
        return UUID.fromString(claims.getSubject());
    }

    public long extractPermissionVersion(Claims claims) {
        return claims.get(CLAIM_PV, Long.class);
    }

    public Set<String> extractRoles(Claims claims) {
        return extractSet(claims, CLAIM_ROLES);
    }

    public Set<String> extractPermissions(Claims claims) {
        return extractSet(claims, CLAIM_PERMS);
    }

    public String extractEmail(Claims claims) {
        return claims.get(CLAIM_EMAIL, String.class);
    }

    private Set<String> extractSet(Claims claims, String key) {
        Object raw = claims.get(key);
        if (raw == null) return Set.of();
        if (!(raw instanceof List<?> list)) {
            throw new IllegalStateException("Invalid claim: " + key);
        }
        return list.stream().map(String.class::cast).collect(Collectors.toUnmodifiableSet());
    }

    public long getRefreshTtlSeconds() {
        return accessTtlSeconds;
    }
}

