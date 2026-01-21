package com.jaypal.authapp.service.auth.operations;

import com.jaypal.authapp.domain.user.service.UserService;
import com.jaypal.authapp.dto.user.UserCreateRequest;
import com.jaypal.authapp.dto.user.UserResponseDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class RegistrationOperation {

    private final UserService userService;

    public UUID execute(UserCreateRequest request) {
        UserResponseDto user = userService.createUser(request);
        return user.id();
    }
}
