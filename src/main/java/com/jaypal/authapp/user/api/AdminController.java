package com.jaypal.authapp.user.api;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.domain.AuditSubjectType;
import com.jaypal.authapp.audit.domain.AuthAuditEvent;
import com.jaypal.authapp.audit.domain.AuthProvider;
import com.jaypal.authapp.user.dto.AdminUserRoleUpdateRequest;
import com.jaypal.authapp.user.dto.AdminUserUpdateRequest;
import com.jaypal.authapp.user.dto.UserCreateRequest;
import com.jaypal.authapp.user.dto.UserResponseDto;
import com.jaypal.authapp.user.application.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
public class AdminController {

    private final UserService userService;

    @AuthAudit(
            event = AuthAuditEvent.ADMIN_USER_CREATED,
            subject = AuditSubjectType.USER_ID,
            provider = AuthProvider.SYSTEM
    )
    @PostMapping
    public ResponseEntity<UserResponseDto> create(
            @RequestBody @Valid UserCreateRequest req
    ) {
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(userService.createUser(req));
    }

    @AuthAudit(
            event = AuthAuditEvent.ADMIN_USER_UPDATED,
            subject = AuditSubjectType.USER_ID,
            provider = AuthProvider.SYSTEM
    )
    @PutMapping("/{id}")
    public UserResponseDto adminUpdate(
            @PathVariable String id,
            @RequestBody AdminUserUpdateRequest req
    ) {
        return userService.adminUpdateUser(id, req);
    }

    @AuthAudit(
            event = AuthAuditEvent.ROLE_ASSIGNED,
            subject = AuditSubjectType.USER_ID,
            provider = AuthProvider.SYSTEM
    )
    @PutMapping("/{id}/roles")
    public UserResponseDto updateUserRoles(
            @PathVariable String id,
            @RequestBody AdminUserRoleUpdateRequest req
    ) {
        return userService.adminUpdateUserRoles(id, req);
    }

    @AuthAudit(
            event = AuthAuditEvent.ADMIN_USER_DELETED,
            subject = AuditSubjectType.USER_ID,
            provider = AuthProvider.SYSTEM
    )
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable String id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}
