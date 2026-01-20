package com.jaypal.authapp.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jaypal.authapp.infrastructure.audit.handler.AuditAccessDeniedHandler;
import com.jaypal.authapp.infrastructure.security.filter.JwtAuthenticationFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

@Slf4j
@Configuration
@RequiredArgsConstructor
@Order(2)
public class ApiSecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final ObjectMapper objectMapper;
    private final AuditAccessDeniedHandler auditAccessDeniedHandler;

    @Bean
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/**")
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .sessionManagement(sm ->
                        sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/v1/auth/**"
                        ).permitAll()
                        .requestMatchers("/api/health", "/api/actuator/health").permitAll()
                        .anyRequest().authenticated()
                )

                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(this::handleAuthenticationFailure)
                        .accessDeniedHandler(auditAccessDeniedHandler)
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    private void handleAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
    ) {
        log.warn("Authentication failed for request: {} - Reason: {}",
                request.getRequestURI(), exception.getMessage());

        sendErrorResponse(
                response,
                request.getRequestURI()
        );
    }

    private void sendErrorResponse(
            HttpServletResponse response,
            String path
    ) {
        try {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("UTF-8");

            final Map<String, Object> errorBody = Map.of(
                    "timestamp", Instant.now().toString(),
                    "status", HttpStatus.UNAUTHORIZED.value(),
                    "error", HttpStatus.UNAUTHORIZED.getReasonPhrase(),
                    "message", "Authentication required",
                    "path", path
            );

            response.getWriter().write(objectMapper.writeValueAsString(errorBody));
            response.getWriter().flush();

        } catch (IOException ex) {
            log.error("Failed to write error response for path: {}", path, ex);
        }
    }
}