package com.owasp.demo.util;

import com.owasp.demo.config.AppConfig;
import org.mindrot.jbcrypt.BCrypt;

/**
 * Hashes and checks stored passwords with bcrypt. The cost comes from
 * {@code auth.bcrypt_cost} in application.yml. Each hash carries its own salt.
 */
public final class PasswordHasher {

    /** Checked when a username does not exist, so a miss costs the same time as a wrong password. */
    private static final String DUMMY_HASH = BCrypt.hashpw("not-a-real-password", BCrypt.gensalt(cost()));

    private PasswordHasher() {}

    private static int cost() {
        return AppConfig.get().getInt("auth.bcrypt_cost");
    }

    /**
     * @param plain the clear-text password
     * @return a bcrypt hash that starts with $2a$
     */
    public static String hash(String plain) {
        return BCrypt.hashpw(plain, BCrypt.gensalt(cost()));
    }

    /**
     * @param plain the clear-text password to test
     * @param stored a stored bcrypt hash
     * @return true if the password matches. False for null input or a value that is not a bcrypt hash.
     */
    public static boolean verify(String plain, String stored) {
        if (plain == null || stored == null) return false;
        try {
            return BCrypt.checkpw(plain, stored);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Burns the same time as a real check. Call it when no user matched.
     *
     * @param plain the password the caller sent
     */
    public static void verifyAgainstDummy(String plain) {
        verify(plain == null ? "" : plain, DUMMY_HASH);
    }
}
