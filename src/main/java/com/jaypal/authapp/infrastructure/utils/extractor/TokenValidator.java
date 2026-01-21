package com.jaypal.authapp.infrastructure.utils.extractor;

import com.jaypal.authapp.exception.auth.InvalidRefreshTokenException;
import com.jaypal.authapp.exception.auth.MissingRefreshTokenException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class TokenValidator {

    private static final int MAX_TOKEN_LENGTH = 2048;
    private static final String VALID_TOKEN_PATTERN = "^[A-Za-z0-9._~-]+$";

    public String validate(String token) {
        log.debug("Validating refresh token (length={})", token.length());

        validateNotBlank(token);
        validateLength(token);
        validateCharacters(token);

        log.debug("Refresh token validation successful");
        return token;
    }

    private void validateNotBlank(String token) {
        if (token.isBlank()) {
            log.debug("Refresh token validation failed: token is blank");
            throw new MissingRefreshTokenException();
        }
    }

    private void validateLength(String token) {
        if (token.length() > MAX_TOKEN_LENGTH) {
            log.warn("Refresh token validation failed: token length exceeds {}", MAX_TOKEN_LENGTH);
            throw new InvalidRefreshTokenException("Refresh token too long");
        }
    }

    private void validateCharacters(String token) {
        if (!token.matches(VALID_TOKEN_PATTERN)) {
            log.warn("Refresh token validation failed: token contains invalid characters");
            throw new InvalidRefreshTokenException("Refresh token has invalid characters");
        }
    }
}
