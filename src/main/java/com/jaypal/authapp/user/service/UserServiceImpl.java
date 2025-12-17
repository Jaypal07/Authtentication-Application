package com.jaypal.authapp.user.service;

import com.jaypal.authapp.common.exception.ResourceNotFoundExceptions;
import com.jaypal.authapp.dto.*;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final ModelMapper mapper;

    @Override
    @Transactional
    public UserResponseDto createUser(UserCreateRequest req) {

        try {
            User user = User.createLocal(
                    req.email(),
                    passwordEncoder.encode(req.password()),
                    req.name()
            );

            return toResponse(userRepository.save(user));

        } catch (DataIntegrityViolationException ex) {
            throw new IllegalArgumentException("Email already exists");
        }
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponseDto getUserById(String userId) {
        return toResponse(find(userId));
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponseDto getUserByEmail(String email) {
        return toResponse(
                userRepository.findByEmail(email)
                        .orElseThrow(() ->
                                new ResourceNotFoundExceptions(
                                        "User not found with given email id"
                                ))
        );
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserResponseDto> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .map(this::toResponse)
                .toList();
    }

    @Override
    @Transactional
    public UserResponseDto updateUser(
            String userId,
            UserUpdateRequest req
    ) {

        User user = find(userId);

        user.updateProfile(req.name(), req.image());

        if (req.password() != null && !req.password().isBlank()) {
            user.changePassword(
                    passwordEncoder.encode(req.password())
            );
        }

        return toResponse(userRepository.save(user));
    }

    @Override
    @Transactional
    public UserResponseDto adminUpdateUser(
            String userId,
            AdminUserUpdateRequest req
    ) {

        User user = find(userId);

        if (req.name() != null) user.updateProfile(req.name(), req.image());
        if (req.roles() != null) user.setRoles(req.roles().stream()
                .map(r -> mapper.map(r, com.jaypal.authapp.user.model.Role.class))
                .collect(java.util.stream.Collectors.toSet()));

        user.setEnabled(req.enabled());

        return toResponse(userRepository.save(user));
    }

    @Override
    @Transactional
    public void deleteUser(String userId) {
        userRepository.delete(find(userId));
    }

    // ---------------- INTERNAL ----------------

    private User find(String id) {
        return userRepository.findById(UUID.fromString(id))
                .orElseThrow(() ->
                        new ResourceNotFoundExceptions(
                                "User not found with ID: " + id
                        ));
    }

    private UserResponseDto toResponse(User user) {
        return mapper.map(user, UserResponseDto.class);
    }
}
