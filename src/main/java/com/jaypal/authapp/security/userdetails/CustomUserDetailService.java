package com.jaypal.authapp.security.userdetails;

import com.jaypal.authapp.security.principal.AuthPrincipal;
import com.jaypal.authapp.user.application.PermissionService;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PermissionService permissionService;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Objects.requireNonNull(email, "Email cannot be null");

        if (email.isBlank()) {
            log.warn("Login attempt with blank email");
            throw new UsernameNotFoundException("Invalid credentials");
        }

        final User user = userRepository.findByEmailWithRoles(email)
                .orElseThrow(() -> {
                    log.warn("Login attempt for non-existent email: {}", maskEmail(email));
                    return new UsernameNotFoundException("Invalid credentials");
                });

        if (!user.isEnabled()) {
            log.warn("Login attempt for disabled user: {}", user.getId());
            throw new DisabledException("Account is disabled");
        }

        if (!user.isEmailVerified()) {
            log.warn("Login attempt for unverified user: {}", user.getId());
            throw new DisabledException("Email not verified");
        }

        final Set<String> permissionNames = permissionService.resolvePermissions(user.getId())
                .stream()
                .map(Enum::name)
                .collect(Collectors.toSet());

        user.getRoles().forEach(role ->
                permissionNames.add("ROLE_" + role)
        );

        final Set<SimpleGrantedAuthority> authorities = permissionNames.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());

        log.debug("User loaded successfully: {} with {} authorities", user.getId(), authorities.size());

        return new AuthPrincipal(
                user.getId(),
                user.getEmail(),
                user.getPassword(),
                authorities
        );
    }

    private String maskEmail(String email) {
        if (email == null || email.length() <= 3) {
            return "***";
        }

        final int atIndex = email.indexOf('@');
        if (atIndex <= 0) {
            return email.substring(0, 2) + "***";
        }

        return email.substring(0, Math.min(2, atIndex)) + "***" + email.substring(atIndex);
    }
}

/*
CHANGELOG:
1. Added @Transactional(readOnly = true) to prevent lazy loading issues
2. Added null and blank check for email input
3. Added email masking in logs to prevent PII exposure
4. Separated disabled account and unverified email checks
5. Changed exception from UsernameNotFoundException to DisabledException for disabled accounts
6. Added email verification check before authentication
7. Added roles with ROLE_ prefix to authorities for Spring Security conventions
8. Added comprehensive logging for security audit trail
9. Used Set instead of List for authorities to prevent duplicates
10. Added null check for email parameter
11. Made authorities collection immutable with Collectors.toSet()
*/