package com.jaypal.authapp.infrastructure.security.filter;

import com.jaypal.authapp.config.utils.JsonUtils;
import com.jaypal.authapp.config.properties.RateLimitProperties;
import com.jaypal.authapp.infrastructure.ratelimit.CidrMatcher;
import com.jaypal.authapp.infrastructure.ratelimit.RateLimitContext;
import com.jaypal.authapp.infrastructure.ratelimit.RedisRateLimiter;
import com.jaypal.authapp.infrastructure.ratelimit.RequestIpResolver;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter {

    private final RedisRateLimiter rateLimiter;
    private final RateLimitProperties properties;
    private final MeterRegistry meterRegistry;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain
    ) throws ServletException, IOException {

        String path = normalize(request.getRequestURI());
        String method = request.getMethod();
        String ip = RequestIpResolver.resolve(request);

        // Hard bypass system endpoints
        if (path.startsWith("/actuator")) {
            chain.doFilter(request, response);
            return;
        }

        // CIDR bypass safety
        if (CidrMatcher.matches(ip, properties.getInternalCidrs())) {
            chain.doFilter(request, response);
            return;
        }

        // Load endpoints safely
        Map<String, RateLimitProperties.Limit> endpoints = properties.getEndpoints();

        RateLimitProperties.Limit defaultLimit =
                endpoints.getOrDefault("default", new RateLimitProperties.Limit(100, 1));

        RateLimitProperties.Limit limit =
                endpoints.getOrDefault(path, defaultLimit);

        // Absolute safety fallback
        if (limit == null) {
            chain.doFilter(request, response);
            return;
        }

        String key = "rl:ip:" + ip + ":" + path;

        RateLimitContext ctx = new RateLimitContext(path, method, "ip");

        boolean allowed = true;

        try {
            allowed = rateLimiter.allow(
                    key,
                    limit.getCapacity(),
                    limit.getRefillPerSecond(),
                    ctx
            );
        } catch (Exception ex) {
            log.error("Redis rate limit failure. Fail-open mode | path={} ip={}", path, ip, ex);
            allowed = true; // Fail-open in prod
        }

        if (!allowed) {
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType("application/json");
            response.getWriter().write(JsonUtils.toJson(Map.of(
                    "status", 429,
                    "error", "Too many requests",
                    "timestamp", Instant.now().toString()
            )));
            return;
        }

        chain.doFilter(request, response);
    }


    private String normalize(String path) {
        if (path.endsWith("/") && path.length() > 1) {
            return path.substring(0, path.length() - 1);
        }
        return path;
    }
}
