package com.jaypal.authapp.infrastructure.utils.extractor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jaypal.authapp.exception.auth.InvalidRefreshTokenException;
import com.jaypal.authapp.exception.auth.MissingRefreshTokenException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.util.ContentCachingRequestWrapper;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class BodyTokenExtractor {

    private static final String REFRESH_BODY_FIELD = "refreshToken";

    private final ObjectMapper objectMapper;

    public Optional<String> extract(HttpServletRequest request) {
        if (!(request instanceof ContentCachingRequestWrapper wrapper)) {
            log.debug("Request is not ContentCachingRequestWrapper; body not readable");
            return Optional.empty();
        }

        byte[] body = wrapper.getContentAsByteArray();
        if (body.length == 0) {
            log.debug("Request body is empty");
            return Optional.empty();
        }

        try {
            return parseTokenFromBody(body);
        } catch (MissingRefreshTokenException ex) {
            throw ex;
        } catch (Exception ex) {
            log.warn("Failed to parse refresh token from request body (invalid JSON)");
            throw new InvalidRefreshTokenException("Malformed refresh token payload");
        }
    }

    private Optional<String> parseTokenFromBody(byte[] body) throws Exception {
        JsonNode root = objectMapper.readTree(body);
        JsonNode tokenNode = root.get(REFRESH_BODY_FIELD);

        if (tokenNode == null) {
            log.debug("Request body does not contain '{}' field", REFRESH_BODY_FIELD);
            return Optional.empty();
        }

        String token = tokenNode.asText();

        if (token.isBlank()) {
            log.debug("Refresh token field '{}' is blank", REFRESH_BODY_FIELD);
            throw new MissingRefreshTokenException();
        }

        return Optional.of(token.trim());
    }
}