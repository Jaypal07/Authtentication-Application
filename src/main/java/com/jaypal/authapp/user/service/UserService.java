package com.jaypal.authapp.user.service;

import com.jaypal.authapp.dto.*;

import java.util.List;

public interface UserService {

    UserResponseDto createUser(UserCreateRequest request);

    UserResponseDto getUserById(String userId);

    UserResponseDto getUserByEmail(String email);

    List<UserResponseDto> getAllUsers();

    UserResponseDto updateUser(String userId, UserUpdateRequest request);

    UserResponseDto adminUpdateUser(
            String userId,
            AdminUserUpdateRequest request
    );

    void deleteUser(String userId);
}
