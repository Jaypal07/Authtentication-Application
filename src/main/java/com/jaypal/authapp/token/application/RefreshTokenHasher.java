package com.jaypal.authapp.token.application;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

@Slf4j
@Component
public class RefreshTokenHasher {

    private static final String ALGORITHM = "SHA-256";
    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

    private MessageDigest digest;

    @PostConstruct
    public void init() {
        try {
            this.digest = MessageDigest.getInstance(ALGORITHM);
            log.info("Token hasher initialized with algorithm: {}", ALGORITHM);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(
                    "Required hash algorithm not available: " + ALGORITHM, ex
            );
        }
    }

    public String hash(String rawToken) {
        Objects.requireNonNull(rawToken, "Raw token cannot be null");

        if (rawToken.isBlank()) {
            throw new IllegalArgumentException("Raw token cannot be blank");
        }

        synchronized (this) {
            digest.reset();
            final byte[] hashed = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return toHex(hashed);
        }
    }

    private static String toHex(byte[] bytes) {
        final char[] hexChars = new char[bytes.length * 2];

        for (int i = 0; i < bytes.length; i++) {
            final int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }

        return new String(hexChars);
    }
}

/*
CHANGELOG:
1. Reused MessageDigest instance instead of creating new one per hash
2. Added @PostConstruct to initialize digest and fail fast
3. Added synchronized block to make digest reuse thread-safe
4. Added null check for rawToken parameter
5. Added blank check for rawToken parameter
6. Added digest.reset() before each hash to ensure clean state
7. Extracted HEX_ARRAY as static constant
8. Added logging on initialization
9. Made toHex method variables final
10. Changed exception message to be more descriptive
*/