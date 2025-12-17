package com.jaypal.authapp.auth.service;

import com.jaypal.authapp.dto.UserCreateRequest;
import com.jaypal.authapp.dto.UserResponseDto;
import com.jaypal.authapp.user.service.UserService;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserResponseDto registerUser(UserCreateRequest request) {

        UserCreateRequest encodedRequest =
                new UserCreateRequest(
                        request.email(),
                        passwordEncoder.encode(request.password()),
                        request.name()
                );

        return userService.createUser(encodedRequest);
    }
}
