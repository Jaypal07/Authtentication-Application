package com.jaypal.authapp.user.application;

import com.jaypal.authapp.user.model.PermissionType;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class PermissionService {

    private final PermissionRepository permissionRepository;

    /**
     * Resolve permissions for a user in a single query.
     * No lazy loading.
     * No entity traversal.
     * No transaction required.
     */
    public Set<PermissionType> resolvePermissions(User user) {
        return permissionRepository.findPermissionTypesByUserId(user.getId());
    }
}
