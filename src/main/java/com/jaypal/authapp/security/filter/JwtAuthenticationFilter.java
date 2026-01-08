package com.jaypal.authapp.security.filter;

import com.jaypal.authapp.security.jwt.JwtService;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import com.jaypal.authapp.user.application.PermissionService;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final PermissionService permissionService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain
    ) throws ServletException, IOException {

        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        String token = header.substring(7).trim();

        // 1️⃣ Parse ONCE. Enforces signature, expiry, issuer.
        Jws<Claims> parsed;
        try {
            parsed = jwtService.parse(token);
        } catch (JwtException ex) {
            chain.doFilter(request, response);
            return;
        }

        // 2️⃣ Enforce access-token usage
        if (!jwtService.isAccessToken(parsed)) {
            chain.doFilter(request, response);
            return;
        }

        // 3️⃣ Do not override existing authentication
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            chain.doFilter(request, response);
            return;
        }

        Claims claims = parsed.getBody();
        UUID userId = jwtService.extractUserId(claims);

        User user = userRepository.findByIdWithRoles(userId)
                .orElseThrow(() -> new JwtException("User not found"));

        if(!user.isEnabled()){
            chain.doFilter(request, response);
            return;
        }

        Set<GrantedAuthority> authorities = new HashSet<>();

        // Roles
        user.getRoles().forEach(r ->
                authorities.add(new SimpleGrantedAuthority(r))
        );

        // Permissions
        permissionService.resolvePermissions(userId).stream()
                .map(Enum::name)
                .map(SimpleGrantedAuthority::new)
                .forEach(authorities::add);

        AuthPrincipal principal = new AuthPrincipal(
                user.getId(),
                user.getEmail(),
                null,
                true,
                authorities
        );

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        principal,
                        null,
                        authorities
                );

        authentication.setDetails(
                new WebAuthenticationDetailsSource().buildDetails(request)
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.equals("/api/v1/auth/login")
                || path.equals("/api/v1/auth/register");
    }
}
