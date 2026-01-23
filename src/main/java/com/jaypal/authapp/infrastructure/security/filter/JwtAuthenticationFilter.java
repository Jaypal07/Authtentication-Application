package com.jaypal.authapp.infrastructure.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jaypal.authapp.domain.user.repository.UserRepository;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import com.jaypal.authapp.infrastructure.security.jwt.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jws;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final int BEARER_PREFIX_LENGTH = 7;

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain chain
    ) throws ServletException, IOException {

        final Optional<String> tokenOpt = extractBearerToken(request);

        if (tokenOpt.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }

        try {
            authenticate(tokenOpt.get(), request);
            log.debug("JWT authentication successful for user: {}",
                    ((AuthPrincipal) SecurityContextHolder.getContext()
                            .getAuthentication()
                            .getPrincipal()).getUserId()
            );

        } catch (ExpiredJwtException ex) {
            log.debug("JWT token expired: {}", ex.getMessage());
            sendUnauthorized(response, "Token expired");
            return;
        } catch (JwtException ex) {
            log.warn("JWT validation failed: {}", ex.getMessage());
            sendUnauthorized(response, "Invalid token");
            return;
        } catch (IllegalArgumentException ex) {
            log.warn("JWT parsing failed: {}", ex.getMessage());
            sendUnauthorized(response, "Malformed token");
            return;
        } catch (Exception ex) {
            log.error("Unexpected error during JWT authentication for request: {}", request.getRequestURI(), ex);
            sendUnauthorized(response, "Authentication failed");
            return;
        }

        chain.doFilter(request, response);
    }

    private Optional<String> extractBearerToken(HttpServletRequest request) {
        final String header = request.getHeader(AUTH_HEADER);

        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            return Optional.empty();
        }

        final String token = header.substring(BEARER_PREFIX_LENGTH).trim();
        return token.isEmpty() ? Optional.empty() : Optional.of(token);
    }

    private void authenticate(String token, HttpServletRequest request) {
        final Jws<Claims> parsed = jwtService.parseAccessToken(token);
        final Claims claims = parsed.getBody();

        final UUID userId = jwtService.extractUserId(claims);
        final long tokenPermissionVersion = jwtService.extractPermissionVersion(claims);

        validatePermissionVersion(userId, tokenPermissionVersion);

        final Set<SimpleGrantedAuthority> authorities = extractAuthorities(claims);
        final AuthPrincipal principal = buildPrincipal(userId, claims, authorities);

        final UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(principal, null, authorities);

        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private void validatePermissionVersion(UUID userId, long tokenPermissionVersion) {
        final Long currentPermissionVersion = userRepository
                .findPermissionVersionById(userId)
                .orElse(null);

        if (currentPermissionVersion == null) {
            log.warn("Token validation failed: User {} not found or deleted", userId);
            throw new IllegalStateException("User not found");
        }

        if (tokenPermissionVersion != currentPermissionVersion) {
            log.warn(
                    "Token validation failed: Permission version mismatch for user {}. Token PV: {}, Current PV: {}",
                    userId, tokenPermissionVersion, currentPermissionVersion
            );
            throw new IllegalStateException("Token permissions outdated");
        }
    }

    private Set<SimpleGrantedAuthority> extractAuthorities(Claims claims) {
        final Set<SimpleGrantedAuthority> authorities = new HashSet<>();

        jwtService.extractRoles(claims)
                .forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));

        jwtService.extractPermissions(claims)
                .forEach(perm -> authorities.add(new SimpleGrantedAuthority(perm)));

        return authorities;
    }

    private AuthPrincipal buildPrincipal(
            UUID userId,
            Claims claims,
            Set<SimpleGrantedAuthority> authorities
    ) {
        return new AuthPrincipal(
                userId,
                jwtService.extractEmail(claims),
                null,
                authorities
        );
    }

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        final String path = request.getRequestURI();
        return path.startsWith("/api/v1/auth/") || path.equals("/api/v1/auth");
    }

    private void sendUnauthorized(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        final Map<String, Object> errorResponse = Map.of(
                "status", 401,
                "error", "Unauthorized",
                "message", message,
                "timestamp", System.currentTimeMillis()
        );

        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}
