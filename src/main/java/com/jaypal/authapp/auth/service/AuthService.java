package com.jaypal.authapp.auth.service;

import com.jaypal.authapp.dto.UserCreateRequest;
import com.jaypal.authapp.dto.UserDto;
import com.jaypal.authapp.dto.UserResponseDto;

public interface AuthService {
    UserResponseDto registerUser(UserCreateRequest userCreateRequest);
}
