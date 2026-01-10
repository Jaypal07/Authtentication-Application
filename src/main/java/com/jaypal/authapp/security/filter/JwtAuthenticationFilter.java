package com.jaypal.authapp.security.filter;

import com.jaypal.authapp.security.jwt.JwtService;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import com.jaypal.authapp.user.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
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

        try {
            Jws<Claims> parsed =
                    jwtService.parseAccessToken(header.substring(7).trim());

            Claims claims = parsed.getBody();
            UUID userId = jwtService.extractUserId(claims);
            long tokenPv = jwtService.extractPermissionVersion(claims);

            long currentPv = userRepository
                    .findPermissionVersionById(userId)
                    .orElseThrow();

            if (tokenPv != currentPv) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            Set<SimpleGrantedAuthority> authorities = new HashSet<>();

            jwtService.extractRoles(claims)
                    .forEach(r -> authorities.add(new SimpleGrantedAuthority(r)));

            jwtService.extractPermissions(claims)
                    .forEach(p -> authorities.add(new SimpleGrantedAuthority(p)));

            AuthPrincipal principal =
                    new AuthPrincipal(
                            userId,
                            jwtService.extractEmail(claims),
                            null,
                            authorities
                    );

            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(
                            principal,
                            null,
                            authorities
                    )
            );

        } catch (Exception ex) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        chain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getRequestURI().startsWith("/api/v1/auth");
    }
}
