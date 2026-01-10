package com.jaypal.authapp.user.application;

import com.jaypal.authapp.audit.application.AuthAuditService;
import com.jaypal.authapp.audit.domain.*;
import com.jaypal.authapp.token.application.RefreshTokenService;
import com.jaypal.authapp.user.model.*;
import com.jaypal.authapp.user.repository.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

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
        Role role = roleRepository.findByType(roleType)
                .orElseThrow(() -> new IllegalStateException("Role not initialized"));

        if (userRoleRepository.existsByUserAndRole(user, role)) return;

        Set<PermissionType> before = permissionService.resolvePermissions(user.getId());

        userRoleRepository.save(
                UserRole.builder()
                        .user(user)
                        .role(role)
                        .assignedAt(Instant.now())
                        .build()
        );
        user.bumpPermissionVersion();
        refreshTokenService.revokeAllForUser(user.getId());

        Set<PermissionType> after = permissionService.resolvePermissions(user.getId());

        auditRoleAssignment(user, roleType);
        auditPermissionDiff(user, before, after);

    }

    @Transactional
    public void removeRole(User user, RoleType roleType) {
        Role role = roleRepository.findByType(roleType)
                .orElseThrow(() -> new IllegalStateException("Role not initialized"));

        Set<PermissionType> before = permissionService.resolvePermissions(user.getId());

        userRoleRepository.deleteByUserAndRole(user, role);
        user.bumpPermissionVersion();
        refreshTokenService.revokeAllForUser(user.getId());

        Set<PermissionType> after = permissionService.resolvePermissions(user.getId());

        auditRoleRemoval(user, roleType);
        auditPermissionDiff(user, before, after);
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
        Set<PermissionType> added = new HashSet<>(after);
        added.removeAll(before);

        Set<PermissionType> removed = new HashSet<>(before);
        removed.removeAll(after);

        for (PermissionType p : added) {
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

        for (PermissionType p : removed) {
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
