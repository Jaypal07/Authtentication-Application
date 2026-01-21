package com.jaypal.authapp.infrastructure.utils.extractor;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Slf4j
@Component
public class HeaderTokenExtractor {

    private static final String REFRESH_HEADER = "X-Refresh-Token";

    public Optional<String> extract(HttpServletRequest request) {
        String value = request.getHeader(REFRESH_HEADER);

        if (value == null) {
            log.debug("Refresh token header '{}' not present", REFRESH_HEADER);
            return Optional.empty();
        }

        if (value.isBlank()) {
            log.debug("Refresh token header '{}' is blank", REFRESH_HEADER);
            return Optional.empty();
        }

        return Optional.of(value.trim());
    }
}
