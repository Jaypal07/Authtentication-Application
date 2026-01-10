package com.jaypal.authapp.security.userdetails;

import com.jaypal.authapp.security.principal.AuthPrincipal;
import com.jaypal.authapp.user.application.PermissionService;
import com.jaypal.authapp.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PermissionService permissionService;

    @Override
    public UserDetails loadUserByUsername(String email) {

        var user = userRepository.findByEmailWithRoles(email)
                .orElseThrow(() ->
                        new UsernameNotFoundException("Invalid credentials"));

        if (!user.isEnabled()) {
            throw new UsernameNotFoundException("User disabled");
        }

        var authorities = permissionService.resolvePermissions(user.getId())
                .stream()
                .map(Enum::name)
                .map(SimpleGrantedAuthority::new)
                .toList();

        return new AuthPrincipal(
                user.getId(),
                user.getEmail(),
                user.getPassword(),
                authorities
        );
    }
}
