package com.sysnormal.security.core.security_core.services.jwt;

import com.sysnormal.commons.core.DefaultDataSwap;
import com.sysnormal.commons.core.utils_core.ObjectUtils;
import com.sysnormal.commons.core.utils_core.TextUtils;
import com.sysnormal.security.auth.auth_core.dtos.AgentAuthDto;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;

public class JwtCoreService {

    private static final Logger logger = LoggerFactory.getLogger(JwtCoreService.class);

    private static JwtParser jwtParser = null;

    protected JwtCoreService() {};

    public static void buildJwtParser(PublicKey publicKey) {
        jwtParser = Jwts.parser()
                .verifyWith(publicKey)
                .build();
    }

    public static JwtParser getJwtParser() {
        return jwtParser;
    }

    public static Claims getClaims(String token) {
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
        return result;
    }

    public static Long getExpiration(String token) {
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
        return ((Number) expObj).longValue();

    }

    public static DefaultDataSwap checkToken(String token){
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
        return result;
    }

}
