package com.jaypal.authapp.user.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Entity
@Table(
        name = "users",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_users_provider_provider_id",
                        columnNames = {"provider", "provider_id"}
                ),
                @UniqueConstraint(
                        name = "uk_users_email",
                        columnNames = {"email"}
                )
        },
        indexes = {
                @Index(name = "idx_users_email", columnList = "email"),
                @Index(name = "idx_users_provider", columnList = "provider, provider_id")
        }
)
@Getter
@Setter(AccessLevel.PRIVATE)
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID id;

    @Column(nullable = false, length = 255)
    private String email;

    @Column(length = 255)
    private String password;

    @Column(nullable = false, length = 255)
    private String name;

    @Column(length = 512)
    private String image;

    @Column(nullable = false)
    private boolean enabled = false;

    @Column(nullable = false)
    private boolean emailVerified = false;

    @Column(nullable = false)
    private long permissionVersion = 0L;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Provider provider;

    @Column(name = "provider_id", nullable = false, length = 255)
    private String providerId;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant updatedAt;

    @OneToMany(
            mappedBy = "user",
            fetch = FetchType.LAZY,
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    @Builder.Default
    private Set<UserRole> userRoles = new HashSet<>();

    public static User createLocal(String email, String password, String name) {
        Objects.requireNonNull(email, "Email cannot be null");
        Objects.requireNonNull(password, "Password cannot be null");
        Objects.requireNonNull(name, "Name cannot be null");

        if (email.isBlank()) {
            throw new IllegalArgumentException("Email cannot be blank");
        }

        if (password.isBlank()) {
            throw new IllegalArgumentException("Password cannot be blank");
        }

        if (name.isBlank()) {
            throw new IllegalArgumentException("Name cannot be blank");
        }

        final UUID id = UUID.randomUUID();
        final Instant now = Instant.now();

        return User.builder()
                .id(id)
                .email(email.toLowerCase().trim())
                .password(password)
                .permissionVersion(0L)
                .name(name.trim())
                .enabled(false)
                .emailVerified(false)
                .provider(Provider.SYSTEM)
                .providerId(id.toString())
                .createdAt(now)
                .updatedAt(now)
                .build();
    }

    public static User createOAuth(
            Provider provider,
            String providerId,
            String email,
            String name,
            String image
    ) {
        Objects.requireNonNull(provider, "Provider cannot be null");
        Objects.requireNonNull(providerId, "Provider ID cannot be null");
        Objects.requireNonNull(email, "Email cannot be null");
        Objects.requireNonNull(name, "Name cannot be null");

        if (providerId.isBlank()) {
            throw new IllegalArgumentException("Provider ID cannot be blank");
        }

        if (email.isBlank()) {
            throw new IllegalArgumentException("Email cannot be blank");
        }

        if (name.isBlank()) {
            throw new IllegalArgumentException("Name cannot be blank");
        }

        final UUID id = UUID.randomUUID();
        final Instant now = Instant.now();

        return User.builder()
                .id(id)
                .email(email.toLowerCase().trim())
                .name(name.trim())
                .image(image)
                .enabled(true)
                .emailVerified(true)
                .permissionVersion(0L)
                .provider(provider)
                .providerId(providerId)
                .createdAt(now)
                .updatedAt(now)
                .build();
    }

    public Set<String> getRoles() {
        return userRoles.stream()
                .map(ur -> ur.getRole().getType().name())
                .collect(Collectors.toUnmodifiableSet());
    }

    public Set<Role> getRoleEntities() {
        return userRoles.stream()
                .map(UserRole::getRole)
                .collect(Collectors.toUnmodifiableSet());
    }

    public void enable() {
        this.enabled = true;
        this.emailVerified = true;
        this.updatedAt = Instant.now();
    }

    public void disable() {
        this.enabled = false;
        this.updatedAt = Instant.now();
    }

    public void changePassword(String encodedPassword) {
        Objects.requireNonNull(encodedPassword, "Encoded password cannot be null");

        if (encodedPassword.isBlank()) {
            throw new IllegalArgumentException("Encoded password cannot be blank");
        }

        this.password = encodedPassword;
        this.updatedAt = Instant.now();
    }

    public void updateProfile(String name, String image) {
        if (name != null && !name.isBlank()) {
            this.name = name.trim();
        }

        if (image != null && !image.isBlank()) {
            this.image = image.trim();
        }

        this.updatedAt = Instant.now();
    }

    public void bumpPermissionVersion() {
        this.permissionVersion++;
        this.updatedAt = Instant.now();
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User user)) return false;
        return Objects.equals(id, user.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}

/*
CHANGELOG:
1. Added explicit emailVerified flag (was incorrectly using enabled)
2. Added null and blank validation to factory methods
3. Added email normalization (toLowerCase + trim) in factories
4. Added name trimming in factories and updateProfile
5. Added length constraints to columns for database optimization
6. Added indexes for common query patterns
7. Added null/blank validation to changePassword
8. Made getRoles() and getRoleEntities() return unmodifiable sets
9. Fixed enable() to set both enabled AND emailVerified flags
10. Added equals() and hashCode() based on ID
11. Added default values for boolean fields
12. Improved updateProfile to ignore blank strings
*/