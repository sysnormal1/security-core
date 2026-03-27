package com.sysnormal.security.core.security_core.services.jwt;

import com.sysnormal.commons.core.DefaultDataSwap;
import com.sysnormal.commons.core.utils_core.ObjectUtils;
import com.sysnormal.commons.core.utils_core.TextUtils;
import com.sysnormal.security.auth.auth_core.dtos.AgentAuthDto;
import com.sysnormal.security.core.security_core.utils.KeyUtils;
import io.jsonwebtoken.*;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

@Getter
@Setter
public class JwtCoreService {

    private static final Logger logger = LoggerFactory.getLogger(JwtCoreService.class);

    private String publicPemFilePath;

    private JwtParser jwtParser = null;

    private String publicPem;
    private PublicKey publicKey;

    protected JwtCoreService() {
        logger.debug("INIT {}.{} {}",this.getClass().getSimpleName(), "JwtCoreService()");
        logger.debug("END {}.{} {}",this.getClass().getSimpleName(), "JwtCoreService()");
    };

    protected JwtCoreService(String publicPem) throws NoSuchAlgorithmException, InvalidKeySpecException {
        logger.debug("INIT {}.{}",this.getClass().getSimpleName(), "JwtCoreService(publicPem)");
        this.setPublicPem(publicPem);
        logger.debug("END {}.{}",this.getClass().getSimpleName(), "JwtCoreService(publicPem)");
    };

    protected JwtCoreService(PublicKey publicKey) {
        logger.debug("INIT {}.{}",this.getClass().getSimpleName(), "JwtCoreService(publicKey)");
        this.setPublicKey(publicKey);
        logger.debug("END {}.{}",this.getClass().getSimpleName(), "JwtCoreService(publicKey)");
    };

    public void setPublicPemFilePath(String publicPemFilePath) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        logger.debug("INIT {}.{}",this.getClass().getSimpleName(), "setPublicPemFilePath");
        this.publicPemFilePath = publicPemFilePath;
        logger.info("setted public key file path: '{}'", this.publicPemFilePath);
        if (TextUtils.hasNotNullText(this.publicPemFilePath)) {
            Path path = Path.of(this.publicPemFilePath);

            logger.debug("Resolved public key path to absolute path: '{}'", path.toAbsolutePath());

            if (!Files.exists(path)) {
                logger.error("Public key file does not exist at path: '{}'", path.toAbsolutePath());
                throw new IllegalStateException("Public key file not found: " + path.toAbsolutePath());
            }

            if (!Files.isReadable(path)) {
                logger.error("Public key file is not readable at path: '{}'", path.toAbsolutePath());
                throw new IllegalStateException("Public key file is not readable: " + path.toAbsolutePath());
            }

            logger.info("Public key file found. Attempting to read file...");

            String pem = Files.readString(path);
            this.setPublicPem(pem);
        }
        logger.debug("END {}.{}",this.getClass().getSimpleName(), "setPublicPemFilePath");
    }

    public void setPublicPem(String publicPem) throws NoSuchAlgorithmException, InvalidKeySpecException {
        logger.debug("INIT {}.{}",this.getClass().getSimpleName(), "setPublicPem");
        this.publicPem = publicPem;
        logger.info("Successfully read public key file ({} bytes).", publicPem.length());
        PublicKey publicKey = KeyUtils.parseRsaPublicKey(publicPem);
        logger.info("Successfully parsed RSA public key.");
        this.setPublicKey(publicKey);
        logger.debug("END {}.{}",this.getClass().getSimpleName(), "setPublicPem");
    }

    public void setPublicKey(PublicKey publicKey) {
        logger.debug("INIT {}.{}",this.getClass().getSimpleName(), "setPublicKey");
        this.publicKey = publicKey;
        buildJwtParser(this.publicKey);
        logger.info("JWT parser successfully initialized.");
        logger.debug("END {}.{}",this.getClass().getSimpleName(), "setPublicKey");
    }

    public void buildJwtParser(PublicKey publicKey) {
        logger.debug("INIT {}.{}",this.getClass().getSimpleName(), "buildJwtParser");
        if (publicKey != null) {
            jwtParser = Jwts.parser()
                    .verifyWith(publicKey)
                    .build();
        }
        logger.debug("END {}.{}",this.getClass().getSimpleName(), "buildJwtParser");
    }

    public Claims getClaims(String token) {
        logger.debug("INIT {}.{}",this.getClass().getSimpleName(), "getClaims");
        Claims result = jwtParser
                .parseSignedClaims(token)
                .getPayload();
        logger.debug(
                "JWT_VALID subject={} agentId={} accessProfileId={} systemId={} expiresIn={}s",
                result.getSubject(),
                result.get("agentId"),
                result.get("systemId"),
                result.get("accessProfileId"),
                result.getExpiration() != null ? (result.getExpiration().getTime() - System.currentTimeMillis()) / 1000 : 0
        );
        logger.debug("END {}.{}",this.getClass().getSimpleName(), "getClaims");
        return result;
    }

    public Long getExpiration(String token) {
        logger.debug("INIT {}.{}",this.getClass().getSimpleName(), "getExpiration");
        logger.debug("token: {}", token);
        if (!TextUtils.hasNotNullText(token)) return null;
        Claims claims = getClaims(token);
        logger.debug("claims: {}", claims);

        // pega o exp
        Object expObj = claims.get("exp");
        logger.debug("exp: {}", expObj);
        if (expObj == null) {
            logger.warn("JWT sem claim 'exp'");
            return null;
        }
        logger.debug("END {}.{}",this.getClass().getSimpleName(), "getExpiration");
        return ((Number) expObj).longValue();

    }

    public DefaultDataSwap checkToken(String token){
        logger.debug("INIT {}.{}",this.getClass().getSimpleName(), "checkToken");
        DefaultDataSwap result = new DefaultDataSwap();
        try {
            Long expiresIn = getExpiration(token); //seconds
            logger.debug("checking token {}, expiresIn {}, now millis {}, seconds remaining {}",token, expiresIn, System.currentTimeMillis(), (expiresIn != null && expiresIn > 0) ? expiresIn - System.currentTimeMillis() / 1000 : "infinit");
            if (TextUtils.hasText(token)) {
                Claims claims = getClaims(token);
                AgentAuthDto agentAuthDto = new AgentAuthDto();
                ObjectUtils.setLongPropertyFromMap(claims,"agentId",agentAuthDto::setAgentId);
                if (agentAuthDto.getAgentId() != null) {
                    ObjectUtils.setLongPropertyFromMap(claims,"systemId",agentAuthDto::setSystemId);
                    ObjectUtils.setLongPropertyFromMap(claims,"accessProfileId",agentAuthDto::setAccessProfileId);
                    result.data = agentAuthDto;
                    result.success = true;
                } else {
                    result.message = "invalid token";
                }
            } else {
                result.httpStatusCode = 401;
                result.message = "missing data";
            }
        } catch (ExpiredJwtException e) {
            result.httpStatusCode = 401;
            result.message = "expired token";
            result.setException(e);
        } catch (io.jsonwebtoken.security.SignatureException e) {
            result.httpStatusCode = 401;
            result.message = "invalid signature";
            result.setException(e);
        } catch (MalformedJwtException e) {
            result.httpStatusCode = 400;
            result.message = "malformed token";
            result.setException(e);
        } catch (Exception e) {
            result.httpStatusCode = 500;
            result.message = "unexpected error";
            result.setException(e);
        }
        logger.debug("END {}.{}",this.getClass().getSimpleName(), "checkToken");
        return result;
    }

}
