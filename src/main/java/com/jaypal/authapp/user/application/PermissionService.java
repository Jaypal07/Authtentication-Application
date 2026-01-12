package com.jaypal.authapp.user.application;

import com.jaypal.authapp.user.model.PermissionType;
import com.jaypal.authapp.user.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class PermissionService {

    private final PermissionRepository permissionRepository;

    @Cacheable(
            value = "userPermissions",
            key = "#userId",
            unless = "#result == null || #result.isEmpty()"
    )
    @Transactional(readOnly = true)
    public Set<PermissionType> resolvePermissions(UUID userId) {
        Objects.requireNonNull(userId, "User ID cannot be null");

        final Set<PermissionType> permissions = permissionRepository.findPermissionTypesByUserId(userId);

        log.debug("Resolved {} permissions for user: {}", permissions.size(), userId);

        return permissions;
    }

    @CacheEvict(value = "userPermissions", key = "#userId")
    public void evictPermissionCache(UUID userId) {
        Objects.requireNonNull(userId, "User ID cannot be null");
        log.debug("Evicted permission cache for user: {}", userId);
    }

    @CacheEvict(value = "userPermissions", allEntries = true)
    public void evictAllPermissionCaches() {
        log.info("Evicted all permission caches");
    }

    public String permissionHash(Set<PermissionType> permissions) {
        Objects.requireNonNull(permissions, "Permissions cannot be null");

        if (permissions.isEmpty()) {
            return "";
        }

        return permissions.stream()
                .map(Enum::name)
                .sorted()
                .collect(Collectors.joining("|"));
    }
}

/*
CHANGELOG:
1. Added @Cacheable for resolvePermissions (critical performance fix)
2. Added cache eviction methods for permission changes
3. Added null checks for all parameters
4. Added logging for cache operations
5. Added empty check in permissionHash
6. Made cache configuration flexible (cache name: "userPermissions")
7. Added unless condition to prevent caching empty results
8. Made method read-only transaction
*/