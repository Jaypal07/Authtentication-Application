package com.jaypal.authapp.user.mapper;

import com.jaypal.authapp.user.dto.RoleDto;
import com.jaypal.authapp.user.dto.UserResponseDto;
import com.jaypal.authapp.user.model.Role;
import com.jaypal.authapp.user.model.User;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

public final class UserMapper {

    private UserMapper() {}

    /* =========================
       DOMAIN → RESPONSE DTO
       ========================= */

    public static UserResponseDto toResponse(User user) {
        if (user == null) {
            return null;
        }

        return new UserResponseDto(
                user.getId(),
                user.getEmail(),
                user.getName(),
                user.getImage(),
                user.isEnabled(),
                user.getProvider(),
                toRoleDtos(user.getRoleEntities()),
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }

    /* =========================
       ROLE MAPPERS (READ ONLY)
       ========================= */

    public static Set<RoleDto> toRoleDtos(Set<Role> roles) {
        if (roles == null || roles.isEmpty()) {
            return Collections.emptySet();
        }

        return roles.stream()
                .map(UserMapper::toRoleDto)
                .collect(Collectors.toUnmodifiableSet());
    }

    public static RoleDto toRoleDto(Role role) {
        if (role == null) {
            return null;
        }

        return new RoleDto(
                role.getId(),
                role.getType().name() // IMPORTANT
        );
    }

    /* =========================
       DTO → DOMAIN
       =========================
       ❌ REMOVED ON PURPOSE
       Roles are NOT mapped from DTOs anymore.
       Role assignment is done via service.
       ========================= */
}
