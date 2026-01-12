package com.jaypal.authapp.user.application;

import com.jaypal.authapp.audit.application.AuthAuditService;
import com.jaypal.authapp.audit.domain.*;
import com.jaypal.authapp.token.application.RefreshTokenService;
import com.jaypal.authapp.user.model.*;
import com.jaypal.authapp.user.repository.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserRoleService {

    private final UserRoleRepository userRoleRepository;
    private final RoleRepository roleRepository;
    private final PermissionService permissionService;
    private final RefreshTokenService refreshTokenService;
    private final AuthAuditService auditService;

    @Transactional
    public void assignRole(User user, RoleType roleType) {
        Objects.requireNonNull(user, "User cannot be null");
        Objects.requireNonNull(roleType, "Role type cannot be null");

        final Role role = roleRepository.findByType(roleType)
                .orElseThrow(() -> new IllegalStateException("Role not initialized: " + roleType));

        if (userRoleRepository.existsByUserAndRole(user, role)) {
            log.debug("Role already assigned - skipping: user={}, role={}", user.getId(), roleType);
            return;
        }

        final Set<PermissionType> permissionsBefore = permissionService.resolvePermissions(user.getId());

        userRoleRepository.save(
                UserRole.builder()
                        .user(user)
                        .role(role)
                        .assignedAt(Instant.now())
                        .build()
        );

        user.bumpPermissionVersion();
        permissionService.evictPermissionCache(user.getId());
        refreshTokenService.revokeAllForUser(user.getId());

        final Set<PermissionType> permissionsAfter = permissionService.resolvePermissions(user.getId());

        auditRoleAssignment(user, roleType);
        auditPermissionDiff(user, permissionsBefore, permissionsAfter);

        log.info("Role assigned: user={}, role={}", user.getId(), roleType);
    }

    @Transactional
    public void removeRole(User user, RoleType roleType) {
        Objects.requireNonNull(user, "User cannot be null");
        Objects.requireNonNull(roleType, "Role type cannot be null");

        final Role role = roleRepository.findByType(roleType)
                .orElseThrow(() -> new IllegalStateException("Role not initialized: " + roleType));

        final Set<PermissionType> permissionsBefore = permissionService.resolvePermissions(user.getId());

        userRoleRepository.deleteByUserAndRole(user, role);

        user.bumpPermissionVersion();
        permissionService.evictPermissionCache(user.getId());
        refreshTokenService.revokeAllForUser(user.getId());

        final Set<PermissionType> permissionsAfter = permissionService.resolvePermissions(user.getId());

        auditRoleRemoval(user, roleType);
        auditPermissionDiff(user, permissionsBefore, permissionsAfter);

        log.info("Role removed: user={}, role={}", user.getId(), roleType);
    }

    private void auditRoleAssignment(User user, RoleType roleType) {
        auditService.record(
                AuditCategory.AUTHORIZATION,
                AuthAuditEvent.ROLE_ASSIGNED,
                AuditOutcome.SUCCESS,
                AuditSubject.userId(user.getId().toString()),
                null,
                AuthProvider.SYSTEM,
                null
        );
    }

    private void auditRoleRemoval(User user, RoleType roleType) {
        auditService.record(
                AuditCategory.AUTHORIZATION,
                AuthAuditEvent.ROLE_REMOVED,
                AuditOutcome.SUCCESS,
                AuditSubject.userId(user.getId().toString()),
                null,
                AuthProvider.SYSTEM,
                null
        );
    }

    private void auditPermissionDiff(
            User user,
            Set<PermissionType> before,
            Set<PermissionType> after
    ) {
        final Set<PermissionType> added = new HashSet<>(after);
        added.removeAll(before);

        final Set<PermissionType> removed = new HashSet<>(before);
        removed.removeAll(after);

        for (PermissionType permission : added) {
            auditService.record(
                    AuditCategory.AUTHORIZATION,
                    AuthAuditEvent.PERMISSION_GRANTED,
                    AuditOutcome.SUCCESS,
                    AuditSubject.userId(user.getId().toString()),
                    null,
                    AuthProvider.SYSTEM,
                    null
            );
        }

        for (PermissionType permission : removed) {
            auditService.record(
                    AuditCategory.AUTHORIZATION,
                    AuthAuditEvent.PERMISSION_REVOKED,
                    AuditOutcome.SUCCESS,
                    AuditSubject.userId(user.getId().toString()),
                    null,
                    AuthProvider.SYSTEM,
                    null
            );
        }
    }
}

/*
CHANGELOG:
1. Added null checks for all method parameters
2. Added permission cache eviction after role changes (CRITICAL)
3. Added early return if role already assigned
4. Added comprehensive logging for all operations
5. Made error messages more descriptive
6. Added final modifiers to local variables
7. Used explicit permission cache eviction instead of relying on refresh
*/