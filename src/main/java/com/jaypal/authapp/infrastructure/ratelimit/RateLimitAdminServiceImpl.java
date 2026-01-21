package com.jaypal.authapp.infrastructure.ratelimit;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.Set;

/**
 * Refactored RateLimitAdminService with improved structure.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RateLimitAdminServiceImpl implements RateLimitAdminService {

    private final StringRedisTemplate redisTemplate;
    private final RateLimitMetricsRecorder metricsRecorder;

    @Override
    @PreAuthorize("hasAuthority('RATE_LIMIT_RESET')")
    public void resetLoginIp(String ip) {
        String key = "rl:login:ip:" + ip;
        deleteKey(key);

        metricsRecorder.recordReset("login_ip");
        log.warn("Admin reset login IP rate limit | ip={}", ip);
    }

    @Override
    @PreAuthorize("hasAuthority('RATE_LIMIT_RESET')")
    public void resetLoginEmail(String email) {
        String normalized = normalizeEmail(email);
        String key = "rl:login:email:" + normalized;
        deleteKey(key);

        metricsRecorder.recordReset("login_email");
        log.warn("Admin reset login email rate limit | email={}", normalized);
    }

    @Override
    @PreAuthorize("hasAuthority('RATE_LIMIT_RESET')")
    public void resetAllIpLimits(String ip) {
        Set<String> keys = redisTemplate.keys("rl:ip:" + ip + ":*");
        int keysDeleted = deleteKeys(keys);

        metricsRecorder.recordReset("all_ip");
        log.warn("Admin reset ALL rate limits for IP | ip={} keys={}", ip, keysDeleted);
    }

    private void deleteKey(String key) {
        redisTemplate.delete(key);
    }

    private int deleteKeys(Set<String> keys) {
        if (keys != null && !keys.isEmpty()) {
            redisTemplate.delete(keys);
            return keys.size();
        }
        return 0;
    }

    private String normalizeEmail(String email) {
        return email.toLowerCase().trim();
    }
}
