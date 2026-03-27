package com.sysnormal.security.core.security_core.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class KeyUtils {

    private static final Logger logger = LoggerFactory.getLogger(KeyUtils.class);

    public static PublicKey parseRsaPublicKey(String pem) throws NoSuchAlgorithmException, InvalidKeySpecException {
        logger.debug("INIT {}.{}",KeyUtils.class.getSimpleName(), "parseRsaPublicKey");
        String publicKeyContent = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(publicKeyContent);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        logger.debug("end {}.{}",KeyUtils.class.getSimpleName(), "parseRsaPublicKey");
        return kf.generatePublic(spec);
    }

    public static PrivateKey parseRsaPrivateKey(String pem) throws NoSuchAlgorithmException, InvalidKeySpecException {
        logger.debug("INIT {}.{}",KeyUtils.class.getSimpleName(), "parseRsaPrivateKey");
        String privateKeyContent = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(privateKeyContent);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        logger.debug("END {}.{}",KeyUtils.class.getSimpleName(), "parseRsaPrivateKey");
        return kf.generatePrivate(spec);
    }

    private KeyUtils() {}
}