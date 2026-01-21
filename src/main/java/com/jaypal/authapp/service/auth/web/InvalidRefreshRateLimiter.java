package com.jaypal.authapp.service.auth.web;

import com.jaypal.authapp.config.properties.RateLimitProperties;
import com.jaypal.authapp.infrastructure.ratelimit.RateLimitContext;
import com.jaypal.authapp.infrastructure.ratelimit.RateLimitExceededException;
import com.jaypal.authapp.infrastructure.ratelimit.RedisRateLimiter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class InvalidRefreshRateLimiter {

    private final RedisRateLimiter rateLimiter;
    private final RateLimitProperties rateLimitProperties;

    public void checkAndEnforce(String ip, Exception ex) {
        RateLimitContext ctx = new RateLimitContext(
                "/api/v1/auth/refresh",
                "POST",
                "invalid-refresh-ip"
        );

        String key = "rl:refresh:invalid:ip:" + ip;

        log.debug(
                "Invalid refresh detected | ip={} reason={} applying rate limit",
                ip,
                ex.getClass().getSimpleName()
        );

        boolean allowed = rateLimiter.allow(
                key,
                rateLimitProperties.getInvalidRefresh().getCapacity(),
                rateLimitProperties.getInvalidRefresh().getRefillPerSecond(),
                ctx
        );

        if (!allowed) {
            log.warn(
                    "Invalid refresh rate limit exceeded | ip={} capacity={} refillPerSecond={}",
                    ip,
                    rateLimitProperties.getInvalidRefresh().getCapacity(),
                    rateLimitProperties.getInvalidRefresh().getRefillPerSecond()
            );
            throw new RateLimitExceededException("Too many refresh token attempts");
        }

        log.warn(
                "Invalid refresh attempt allowed | ip={} reason={}",
                ip,
                ex.getClass().getSimpleName()
        );
    }
}