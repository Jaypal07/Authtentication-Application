package com.jaypal.authapp.user.mapper;

import com.jaypal.authapp.dto.RoleDto;
import com.jaypal.authapp.dto.UserResponseDto;
import com.jaypal.authapp.user.model.User;

import java.util.stream.Collectors;

public final class UserMapper {

    private UserMapper() {}

    public static UserResponseDto toResponse(User user) {
        return new UserResponseDto(
                user.getId(),
                user.getEmail(),
                user.getName(),
                user.getImage(),
                user.isEnabled(),
                user.getProvider(),
                user.getRoles() == null
                        ? java.util.Set.of()
                        : user.getRoles().stream()
                        .map(r -> new RoleDto(r.getId(), r.getName()))
                        .collect(Collectors.toSet()),
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }
}
