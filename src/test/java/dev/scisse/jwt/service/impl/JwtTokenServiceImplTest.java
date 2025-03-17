package dev.scisse.jwt.service.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
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
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import dev.scisse.jwt.config.JwtProperties;
import dev.scisse.jwt.exception.JwtException;
import dev.scisse.jwt.exception.TokenExpiredException;
import dev.scisse.jwt.model.JwtToken;
import dev.scisse.jwt.service.TokenBlacklistService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@ExtendWith(MockitoExtension.class)
public class JwtTokenServiceImplTest {

    @Mock
    private TokenBlacklistService tokenBlacklistService;

    @Mock
    private Logger logger;

    @Spy
    private JwtProperties jwtProperties = new JwtProperties();

    @InjectMocks
    private JwtTokenServiceImpl jwtTokenService;

    private SecretKey key;
    private String validToken;
    private String expiredToken;
    private String subject = "testUser";

    @BeforeEach
    public void setUp() {
        // Configure JWT properties
        jwtProperties.setSecret("thisIsAVeryLongSecretKeyForTestingPurposesOnly12345");
        jwtProperties.setExpirationMs(3600000L); // 1 hour
        jwtProperties.setIssuer("jwt-starter-test");
        
        // Create the signing key
        key = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
        
        // Set the key in the service
        try {
            java.lang.reflect.Field keyField = JwtTokenServiceImpl.class.getDeclaredField("key");
            keyField.setAccessible(true);
            keyField.set(jwtTokenService, key);
        } catch (Exception e) {
            fail("Failed to set key field: " + e.getMessage());
        }
        
        Date now = new Date();
        Date expiry = new Date(now.getTime() + 3600000);
        
        validToken = Jwts.builder()
                .subject(subject)
                .issuedAt(now)
                .expiration(expiry)
                .issuer(jwtProperties.getIssuer())
                .signWith(key, Jwts.SIG.HS512)
                .compact();
        
        Date pastDate = new Date(now.getTime() - 3600000);
        expiredToken = Jwts.builder()
                .subject(subject)
                .issuedAt(pastDate)
                .expiration(new Date(pastDate.getTime() + 1000)) // Expired 1 second after issuance
                .issuer(jwtProperties.getIssuer())
                .signWith(key, Jwts.SIG.HS512)
                .compact();
    }

    @Test
    public void testGenerateToken_WithSubjectOnly() {
        // When
        JwtToken token = jwtTokenService.generateToken(subject);
        
        // Then
        assertNotNull(token);
        assertEquals(subject, token.getSubject());
        assertNotNull(token.getToken());
        assertNotNull(token.getIssuedAt());
        assertNotNull(token.getExpiration());
        assertNotNull(token.getClaims());
        assertTrue(token.getClaims().isEmpty());
    }

    @Test
    public void testGenerateToken_WithClaims() {
        // Given
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", "ADMIN");
        claims.put("userId", 123);
        
        // When
        JwtToken token = jwtTokenService.generateToken(subject, claims);
        
        // Then
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
    public void testValidateToken_ValidToken() throws Exception {
        // Given
        when(tokenBlacklistService.isBlacklisted(anyString())).thenReturn(false);
        
        // When
        JwtToken token = jwtTokenService.validateToken(validToken);
        
        // Then
        assertNotNull(token);
        assertEquals(subject, token.getSubject());
        assertEquals(validToken, token.getToken());
        assertNotNull(token.getIssuedAt());
        assertNotNull(token.getExpiration());
    }

    @Test
    public void testValidateToken_ExpiredToken() {
        // Given
        when(tokenBlacklistService.isBlacklisted(anyString())).thenReturn(false);
        
        // When/Then
        assertThrows(TokenExpiredException.class, () -> {
            jwtTokenService.validateToken(expiredToken);
        });
    }

    @Test
    public void testValidateToken_BlacklistedToken() {
        // Given
        when(tokenBlacklistService.isBlacklisted(validToken)).thenReturn(true);
        
        // When/Then
        JwtException exception = assertThrows(JwtException.class, () -> {
            jwtTokenService.validateToken(validToken);
        });
        
        assertEquals("JWT token has been revoked", exception.getMessage());
    }

    @Test
    public void testGetSubjectFromToken() {
        // When
        String extractedSubject = jwtTokenService.getSubjectFromToken(validToken);
        
        // Then
        assertEquals(subject, extractedSubject);
    }

    @Test
    public void testIsTokenExpired_ValidToken() {
        // When
        boolean isExpired = jwtTokenService.isTokenExpired(validToken);
        
        // Then
        assertFalse(isExpired);
    }

    @Test
    public void testIsTokenExpired_ExpiredToken() {
        // When
        boolean isExpired = jwtTokenService.isTokenExpired(expiredToken);
        
        // Then
        assertTrue(isExpired);
    }

    @Test
    public void testRefreshToken() throws Exception {
        // Given
        when(tokenBlacklistService.isBlacklisted(anyString())).thenReturn(false);
        
        // When
        JwtToken refreshedToken = jwtTokenService.refreshToken(validToken);
        
        // Then
        assertNotNull(refreshedToken);
        assertNotEquals(validToken, refreshedToken.getToken());
        assertEquals(subject, refreshedToken.getSubject());
        
        // Verify the old token was blacklisted
        verify(tokenBlacklistService).blacklistToken(eq(validToken), anyLong());
    }
}