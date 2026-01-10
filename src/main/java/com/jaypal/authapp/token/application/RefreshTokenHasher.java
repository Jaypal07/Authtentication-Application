package com.jaypal.authapp.token.application;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Hashes refresh token material before persistence.
 *
 * Security guarantees:
 * - Raw refresh tokens are NEVER stored
 * - Hash is deterministic
 * - One-way (non-reversible)
 * - Safe if database is compromised
 */
@Component
public class RefreshTokenHasher {

    private static final String ALGORITHM = "SHA-256";

    public String hash(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new IllegalArgumentException("rawToken must not be blank");
        }

        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM);
            byte[] hashed = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return toHex(hashed);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(
                    "Required hash algorithm not available: " + ALGORITHM,
                    ex
            );
        }
    }

    private static String toHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }

        return new String(hexChars);
    }
}
