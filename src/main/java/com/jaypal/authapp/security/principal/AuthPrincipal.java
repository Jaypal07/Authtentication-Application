package com.jaypal.authapp.security.principal;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.UUID;

public final class AuthPrincipal implements UserDetails {

    private final UUID userId;
    private final String email;
    private final String password; // ✅ REQUIRED for authentication
    private final Collection<? extends GrantedAuthority> authorities;

    public AuthPrincipal(
            UUID userId,
            String email,
            String password,
            Collection<? extends GrantedAuthority> authorities
    ) {
        this.userId = userId;
        this.email = email;
        this.password = password;
        this.authorities = authorities;
    }

    // ---------- Custom getters ----------

    public UUID getUserId() {
        return userId;
    }

    public String getEmail() {
        return email;
    }

    // ---------- UserDetails ----------

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    /**
     * MUST return encoded password for Spring Security
     */
    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

}
