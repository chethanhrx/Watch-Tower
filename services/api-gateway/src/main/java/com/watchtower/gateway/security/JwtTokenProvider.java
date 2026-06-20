package com.watchtower.gateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

/**
 * Handles JWT token creation, validation, and claims extraction.
 * Uses HMAC-SHA256 signing for simplicity; production would use RS256 with key rotation.
 */
@Component
public class JwtTokenProvider {

    @Value("${watchtower.jwt.secret}")
    private String jwtSecret;

    @Value("${watchtower.jwt.expiration-ms:900000}")  // 15 minutes
    private long accessTokenExpirationMs;

    @Value("${watchtower.jwt.refresh-expiration-ms:604800000}")  // 7 days
    private long refreshTokenExpirationMs;

    private SecretKey signingKey;

    @PostConstruct
    public void init() {
        this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(Long userId, String username, String role) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(username)
                .claim("userId", userId)
                .claim("role", role)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(accessTokenExpirationMs)))
                .signWith(signingKey)
                .compact();
    }

    public String generateRefreshToken(String username) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(username)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(refreshTokenExpirationMs)))
                .signWith(signingKey)
                .compact();
    }

    public Claims validateAndExtractClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean isTokenValid(String token) {
        try {
            validateAndExtractClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public String getUsernameFromToken(String token) {
        return validateAndExtractClaims(token).getSubject();
    }

    public String getRoleFromToken(String token) {
        return validateAndExtractClaims(token).get("role", String.class);
    }

    public Long getUserIdFromToken(String token) {
        Number userId = validateAndExtractClaims(token).get("userId", Number.class);
        return userId != null ? userId.longValue() : null;
    }
}
