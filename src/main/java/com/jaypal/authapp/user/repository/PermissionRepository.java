package com.jaypal.authapp.user.repository;

import com.jaypal.authapp.user.model.Permission;
import com.jaypal.authapp.user.model.PermissionType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public interface PermissionRepository extends JpaRepository<Permission, UUID> {

    Optional<Permission> findByType(PermissionType type);
    @Query("""
        select distinct p.type
        from User u
        join u.userRoles ur
        join ur.role r
        join RolePermission rp on rp.role = r
        join rp.permission p
        where u.id = :userId
    """)
    Set<PermissionType> findPermissionTypesByUserId(@Param("userId") UUID userId);
}
