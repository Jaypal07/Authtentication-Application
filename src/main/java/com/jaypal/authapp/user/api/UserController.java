package com.jaypal.authapp.user.api;

import com.jaypal.authapp.security.principal.AuthPrincipal;
import com.jaypal.authapp.user.dto.UserResponseDto;
import com.jaypal.authapp.user.dto.UserUpdateRequest;
import com.jaypal.authapp.user.application.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Objects;

@Slf4j
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PreAuthorize("isAuthenticated()")
    @GetMapping("/me")
    public ResponseEntity<UserResponseDto> getCurrentUser(
            @AuthenticationPrincipal AuthPrincipal principal
    ) {
        Objects.requireNonNull(principal, "Principal cannot be null");

        final UserResponseDto user = userService.getUserById(principal.getUserId().toString());

        return ResponseEntity.ok(user);
    }

    @PreAuthorize("isAuthenticated()")
    @PutMapping("/{userId}")
    public ResponseEntity<UserResponseDto> updateUser(
            @PathVariable String userId,
            @Valid @RequestBody UserUpdateRequest request,
            @AuthenticationPrincipal AuthPrincipal principal
    ) {
        Objects.requireNonNull(principal, "Principal cannot be null");

        validateOwnership(userId, principal);

        final UserResponseDto user = userService.updateUser(userId, request);

        log.info("User updated their profile - ID: {}", userId);

        return ResponseEntity.ok(user);
    }

    @PreAuthorize("isAuthenticated()")
    @DeleteMapping("/me")
    public ResponseEntity<Map<String, String>> deleteAccount(
            @AuthenticationPrincipal AuthPrincipal principal
    ) {
        Objects.requireNonNull(principal, "Principal cannot be null");

        final String userId = principal.getUserId().toString();

        userService.deleteUser(userId);

        log.info("User deleted their account - ID: {}", userId);

        return ResponseEntity.ok(Map.of(
                "message", "Account deleted successfully"
        ));
    }

    private void validateOwnership(String userId, AuthPrincipal principal) {
        if (!principal.getUserId().toString().equals(userId)) {
            log.warn("User {} attempted to modify user {}", principal.getUserId(), userId);
            throw new AccessDeniedException("You can only modify your own profile");
        }
    }
}

/*
CHANGELOG:
1. CRITICAL: Added ownership validation - users can only update themselves
2. Added GET /me endpoint for current user info
3. Added DELETE /me endpoint for account self-deletion
4. Added @AuthenticationPrincipal to all methods
5. Added null checks for principal
6. Added @PreAuthorize to all endpoints
7. Added logging for user actions
8. Made endpoints return ResponseEntity for consistency
9. Added validateOwnership helper method
10. Made delete return success message instead of void
*/