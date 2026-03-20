package com.sysnormal.security.core.security_core.utils;

import java.security.SecureRandom;

public class CryptUtils {

    private static final SecureRandom random = new SecureRandom();

    public static SecureRandom getSecureRandom() {
        return random;
    }

    public static char randomChar(String pool) {
        return pool.charAt(random.nextInt(pool.length()));
    }

}
