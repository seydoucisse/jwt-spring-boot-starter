package dev.scisse.jwt.service.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import dev.scisse.jwt.config.JwtProperties;
import dev.scisse.jwt.exception.JwtException;
import dev.scisse.jwt.exception.TokenExpiredException;
import dev.scisse.jwt.model.JwtToken;
import dev.scisse.jwt.service.TokenBlacklistService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@ExtendWith(MockitoExtension.class)
class JwtTokenServiceImplTest {

    @Mock
    private TokenBlacklistService tokenBlacklistService;

    private JwtProperties jwtProperties;

    private JwtTokenServiceImpl jwtTokenService;

    private static String validToken;
    private static String expiredToken;
    private final String subject = "testUser";

    @BeforeEach
    void setUp() {
        String secret = "A".repeat(64);
        long expirationMs = 3600000L; // 1 hour
        String issuer = "jwt-starter-test";
        
        jwtProperties = new JwtProperties(
            secret,
            expirationMs,
            0,
            0,
            issuer,
            null,
            true,
            "Authorization",
            "Bearer "
        );
        
        SecretKey key = Keys.hmacShaKeyFor(jwtProperties.secret().getBytes(StandardCharsets.UTF_8));

        jwtTokenService = new JwtTokenServiceImpl(jwtProperties, tokenBlacklistService);
        
        Date now = new Date();
        Date expiry = new Date(now.getTime() + 3600000);
        
        validToken = Jwts.builder()
                .subject(subject)
                .issuedAt(now)
                .expiration(expiry)
                .issuer(jwtProperties.issuer())
                .signWith(key, Jwts.SIG.HS512)
                .compact();
        
        Date pastDate = new Date(now.getTime() - (1000L * 60 * 4));
        expiredToken = Jwts.builder()
                .subject(subject)
                .issuedAt(pastDate)
                .expiration(new Date(pastDate.getTime() + 10000))
                .issuer(jwtProperties.issuer())
                .signWith(key, Jwts.SIG.HS512)
                .compact();
    }

    @Test
    void shouldGenerateValidTokenWithDefaultClaims() {
        JwtToken token = jwtTokenService.generateToken(subject);

        assertNotNull(token);
        assertEquals(subject, token.getSubject());
        assertNotNull(token.getToken());
        assertNotNull(token.getIssuedAt());
        assertNotNull(token.getExpiration());
        assertNotNull(token.getClaims());
        assertTrue(token.getClaims().isEmpty());
    }

    @Test
    void shouldGenerateValidTokenWithCustomClaims() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", "ADMIN");
        claims.put("userId", 123);

        JwtToken token = jwtTokenService.generateToken(subject, claims);

        assertNotNull(token);
        assertEquals(subject, token.getSubject());
        assertNotNull(token.getToken());
        assertNotNull(token.getIssuedAt());
        assertNotNull(token.getExpiration());
        assertNotNull(token.getClaims());
        assertEquals(2, token.getClaims().size());
        assertEquals("ADMIN", token.getClaims().get("role"));
        assertEquals(123, token.getClaims().get("userId"));
    }

    @Test
    void shouldValidateToken() {
        when(tokenBlacklistService.isBlacklisted(anyString())).thenReturn(false);

        JwtToken token = jwtTokenService.validateToken(validToken);

        assertNotNull(token);
        assertEquals(subject, token.getSubject());
        assertEquals(validToken, token.getToken());
        assertNotNull(token.getIssuedAt());
        assertNotNull(token.getExpiration());
    }

    @Test
    void shouldThrowTokenExpiredExceptionWhenTokenExpired() {
        when(tokenBlacklistService.isBlacklisted(anyString())).thenReturn(false);

        assertThrows(TokenExpiredException.class, () -> jwtTokenService.validateToken(expiredToken));
    }

    @Test
    void shouldThrowJwtExceptionWhenTokenInvalid() {
        when(tokenBlacklistService.isBlacklisted(validToken)).thenReturn(true);

        JwtException exception = assertThrows(JwtException.class, () -> jwtTokenService.validateToken(validToken));
        assertEquals("Invalid JWT token: JWT token has been revoked", exception.getMessage());
    }

    @Test
    void shouldGetSubjectFromToken() {
        String extractedSubject = jwtTokenService.getSubjectFromToken(validToken);

        assertEquals(subject, extractedSubject);
    }

    @Test
    void shouldReturnFalseWhenTokenValid() {
        boolean isExpired = jwtTokenService.isTokenExpired(validToken);

        assertFalse(isExpired);
    }

    @Test
    void shouldReturnTrueWhenTokenExpired() {
        boolean isExpired = jwtTokenService.isTokenExpired(expiredToken);

        assertTrue(isExpired);
    }

    @Test
    void shouldRefreshValidToken() {
        when(tokenBlacklistService.isBlacklisted(anyString())).thenReturn(false);

        JwtToken refreshedToken = jwtTokenService.refreshToken(validToken);

        assertNotNull(refreshedToken);
        assertNotEquals(validToken, refreshedToken.getToken());
        assertEquals(subject, refreshedToken.getSubject());
        verify(tokenBlacklistService).blacklistToken(eq(validToken), anyLong());
    }

    @Test
    void shouldRefreshExpiredToken() {
        JwtToken refreshedToken = jwtTokenService.refreshToken(expiredToken);

        assertNotNull(refreshedToken);
        assertNotEquals(expiredToken, refreshedToken.getToken());
        assertEquals(subject, refreshedToken.getSubject());
        verify(tokenBlacklistService, never()).blacklistToken(eq(expiredToken), anyLong());
    }
}