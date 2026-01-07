package com.jaypal.authapp.user.application;

import com.jaypal.authapp.user.dto.*;
import com.jaypal.authapp.user.exception.EmailAlreadyExistsException;
import com.jaypal.authapp.user.exception.ResourceNotFoundException;
import com.jaypal.authapp.user.mapper.UserMapper;
import com.jaypal.authapp.user.model.PermissionType;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserProvisioningService userProvisioningService;
    private final UserRoleService userRoleService;
    private final PermissionService permissionService;

    /* =========================
       LOCAL REGISTRATION
       ========================= */

    @Override
    @Transactional
    public UserResponseDto createUser(UserCreateRequest req) {
        try {
            User user = User.createLocal(
                    req.email(),
                    passwordEncoder.encode(req.password()),
                    req.name()
            );

            User saved = userRepository.save(user);
            userProvisioningService.provisionNewUser(saved);

            return UserMapper.toResponse(saved);

        } catch (DataIntegrityViolationException ex) {
            throw new EmailAlreadyExistsException();
        }
    }

    /* =========================
       OAUTH PROVISIONING
       ========================= */

    @Transactional
    public User provisionOAuthUser(User oauthUser) {
        User saved = userRepository.save(oauthUser);
        userProvisioningService.provisionNewUser(saved);
        return saved;
    }

    /* =========================
       INTERNAL DOMAIN CREATION
       ========================= */

    @Override
    @Transactional
    public User createAndReturnDomainUser(UserCreateRequest req) {
        try {
            User user = User.createLocal(
                    req.email(),
                    passwordEncoder.encode(req.password()),
                    req.name()
            );

            User saved = userRepository.save(user);
            userProvisioningService.provisionNewUser(saved);

            return saved;

        } catch (DataIntegrityViolationException ex) {
            throw new EmailAlreadyExistsException();
        }
    }

    /* =========================
       READ OPERATIONS
       ========================= */

    @Override
    @PreAuthorize("hasAuthority('USER_READ')")
    @Transactional(readOnly = true)
    public UserResponseDto getUserById(String userId) {
        User user = find(userId);
        Set<PermissionType> permissions = permissionService.resolvePermissions(user);
        return UserMapper.toResponse(user, permissions);
    }

    @Override
    @PreAuthorize("hasAuthority('USER_READ')")
    @Transactional(readOnly = true)
    public UserResponseDto getUserByEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(ResourceNotFoundException::new);

        Set<PermissionType> permissions = permissionService.resolvePermissions(user);
        return UserMapper.toResponse(user, permissions);
    }

    @Override
    @PreAuthorize("hasAuthority('USER_READ')")
    @Transactional(readOnly = true)
    public List<UserResponseDto> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .map(u -> UserMapper.toResponse(
                        u,
                        permissionService.resolvePermissions(u)
                ))
                .toList();
    }

    /* =========================
       SELF UPDATE
       ========================= */

    @Override
    @PreAuthorize("#userId == authentication.principal.id")
    @Transactional
    public UserResponseDto updateUser(String userId, UserUpdateRequest req) {
        User user = find(userId);

        user.updateProfile(req.name(), req.image());

        if (req.password() != null && !req.password().isBlank()) {
            user.changePassword(passwordEncoder.encode(req.password()));
        }

        return UserMapper.toResponse(user);
    }

    /* =========================
       ADMIN UPDATE
       ========================= */

    @Override
    @PreAuthorize("hasAuthority('USER_UPDATE')")
    @Transactional
    public UserResponseDto adminUpdateUser(String userId, AdminUserUpdateRequest req) {
        User user = find(userId);

        if (req.name() != null || req.image() != null) {
            user.updateProfile(req.name(), req.image());
        }

        if (req.enabled() != null) {
            if (req.enabled()) user.enable();
            else user.disable();
        }

        Set<PermissionType> permissions = permissionService.resolvePermissions(user);
        return UserMapper.toResponse(user, permissions);
    }

    @Override
    @PreAuthorize("hasAuthority('USER_ROLE_ASSIGN')")
    @Transactional
    public UserResponseDto adminUpdateUserRoles(
            String userId,
            AdminUserRoleUpdateRequest req
    ) {
        User user = find(userId);

        if (req.addRoles() != null) {
            req.addRoles().forEach(r ->
                    userRoleService.assignRole(
                            user,
                            Enum.valueOf(com.jaypal.authapp.user.model.RoleType.class, r)
                    )
            );
        }

        if (req.removeRoles() != null) {
            req.removeRoles().forEach(r ->
                    userRoleService.removeRole(
                            user,
                            Enum.valueOf(com.jaypal.authapp.user.model.RoleType.class, r)
                    )
            );
        }

        Set<PermissionType> permissions = permissionService.resolvePermissions(user);
        return UserMapper.toResponse(user, permissions);
    }

    @Override
    @PreAuthorize("hasAuthority('USER_DISABLE')")
    @Transactional
    public void deleteUser(String userId) {
        userRepository.delete(find(userId));
    }

    /* =========================
       INTERNAL
       ========================= */

    private User find(String id) {
        return userRepository.findById(UUID.fromString(id))
                .orElseThrow(() ->
                        new ResourceNotFoundException("User not found with ID: " + id)
                );
    }
}
