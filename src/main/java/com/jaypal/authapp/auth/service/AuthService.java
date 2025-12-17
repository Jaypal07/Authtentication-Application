package com.jaypal.authapp.auth.service;

import com.jaypal.authapp.dto.UserDto;

public interface AuthService {
    UserDto registerUser(UserDto userDto);
}
