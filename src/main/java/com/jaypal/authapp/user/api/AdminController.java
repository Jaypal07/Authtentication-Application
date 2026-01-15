package com.jaypal.authapp.user.api;

import com.jaypal.authapp.user.application.UserService;
import com.jaypal.authapp.user.dto.*;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/v1/admin/users")
@RequiredArgsConstructor
public class AdminController {

    private final UserService userService;

    @PreAuthorize("hasAuthority('USER_UPDATE')")
    @PostMapping
    public ResponseEntity<UserResponseDto> createUser(
            @RequestBody @Valid UserCreateRequest request
    ) {
        UserResponseDto user = userService.createUser(request);
        log.info("Admin created user - ID={}", user.id());
        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }

    @PreAuthorize("hasAuthority('USER_READ')")
    @GetMapping("/{userId}")
    public ResponseEntity<UserResponseDto> getUser(@PathVariable UUID userId) {
        return ResponseEntity.ok(userService.getUserById(userId));
    }

    @PreAuthorize("hasAuthority('USER_READ')")
    @GetMapping("/by-email")
    public ResponseEntity<UserResponseDto> getUserByEmail(@RequestParam String email) {
        return ResponseEntity.ok(userService.getUserByEmail(email));
    }

    @PreAuthorize("hasAuthority('USER_READ')")
    @GetMapping
    public ResponseEntity<List<UserResponseDto>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @PreAuthorize("hasAuthority('USER_UPDATE')")
    @PutMapping("/{userId}")
    public ResponseEntity<UserResponseDto> updateUser(
            @PathVariable UUID userId,
            @RequestBody @Valid AdminUserUpdateRequest request
    ) {
        UserResponseDto user =
                userService.adminUpdateUser(userId, request);

        log.info("Admin updated user - ID={}", userId);
        return ResponseEntity.ok(user);
    }

    @PreAuthorize("hasAuthority('USER_ROLE_ASSIGN')")
    @PutMapping("/{userId}/roles")
    public ResponseEntity<UserResponseDto> updateUserRoles(
            @PathVariable UUID userId,
            @RequestBody @Valid AdminUserRoleUpdateRequest request
    ) {
        UserResponseDto user =
                userService.adminUpdateUserRoles(userId, request);

        log.info("Admin updated user roles - ID={}", userId);
        return ResponseEntity.ok(user);
    }

    @PreAuthorize("hasAuthority('USER_DISABLE')")
    @DeleteMapping("/{userId}")
    public ResponseEntity<Map<String, Serializable>> disableUser(
            @PathVariable UUID userId
    ) {
        userService.adminDisableUser(userId);

        log.info("Admin disabled user - ID={}", userId);

        return ResponseEntity.ok(Map.of(
                "message", "User disabled successfully",
                "userId", userId
        ));
    }
}
