/*
 * Copyright (C) 2025 seydoucisse.github.io
 *
 * Licensed under the MIT License (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/MIT
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package dev.scisse.jwt.service.impl;

import dev.scisse.jwt.config.JwtProperties;
import dev.scisse.jwt.exception.JwtException;
import dev.scisse.jwt.exception.TokenExpiredException;
import dev.scisse.jwt.model.JwtToken;
import dev.scisse.jwt.service.JwtTokenService;
import dev.scisse.jwt.service.TokenBlacklistService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Default implementation of the JwtTokenService interface.
 * <p>
 * This implementation uses the jjwt library to generate, validate, and process
 * JWT tokens. It provides all the functionality defined in the JwtTokenService
 * interface, including token generation, validation, refreshing, and invalidation.
 * 
 * <p>
 * Key features:
 * <ul>
 *   <li>Token generation with custom claims</li>
 *   <li>Token validation with signature verification</li>
 *   <li>Token refreshing with configurable refresh window</li>
 *   <li>Token invalidation via blacklisting</li>
 *   <li>Extraction of token information</li>
 * </ul>
 * 
 * <p>
 * This implementation uses HMAC-SHA512 for token signing and relies on the
 * provided JwtProperties for configuration values like secret key, token
 * expiration time, and issuer.
 * 
 * @author Seydou CISSE
 * @since 0.1.0
 * @see dev.scisse.jwt.service.JwtTokenService
 * @see dev.scisse.jwt.config.JwtProperties
 * @see dev.scisse.jwt.service.TokenBlacklistService
 * @see dev.scisse.jwt.model.JwtToken
 */
@Service
public class JwtTokenServiceImpl implements JwtTokenService {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenServiceImpl.class);
    
    private final JwtProperties jwtProperties;
    private final SecretKey key;
    private final TokenBlacklistService tokenBlacklistService;
    
    /**
     * Constructs a new JwtTokenServiceImpl with the specified properties and services.
     * <p>
     * Initializes the service with the JWT properties and token blacklist service.
     * Also creates a SecretKey from the configured secret for token signing and validation.
     *
     * @param jwtProperties The JWT configuration properties
     * @param tokenBlacklistService The service for blacklisting tokens
     */
    public JwtTokenServiceImpl(JwtProperties jwtProperties, TokenBlacklistService tokenBlacklistService) {
        this.jwtProperties = jwtProperties;
        this.key = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes());
        this.tokenBlacklistService = tokenBlacklistService;
    }

    /**
     * Generates a JWT token for the given subject and claims.
     * <p>
     * Creates a new JWT token with the specified subject and additional claims.
     * The token includes standard claims like issuedAt, expiration, and issuer,
     * as well as any custom claims provided.
     * 
     * <p>
     * The token is signed using HMAC-SHA512 with the configured secret key.
     *
     * @param subject The subject of the token (usually a username or user ID)
     * @param claims Additional claims to include in the token
     * @return A JwtToken object containing the token string and its metadata
     */
    @Override
    public JwtToken generateToken(String subject, Map<String, Object> claims) {
        logger.debug("Generating token for subject: {}", subject);
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtProperties.getExpirationMs());
        
        Map<String, Object> allClaims = new HashMap<>(claims);
        
        String token = Jwts.builder()
                .claims(allClaims)
                .subject(subject)
                .issuedAt(now)
                .expiration(expiryDate)
                .issuer(jwtProperties.getIssuer())
                .signWith(key, Jwts.SIG.HS512)
                .compact();
        
        logger.debug("Token generated successfully for subject: {}", subject);
        return new JwtToken(token, subject, now, expiryDate, allClaims);
    }

    /**
     * Generates a JWT token for the given subject without additional claims.
     * <p>
     * This is a convenience method that calls {@link #generateToken(String, Map)}
     * with an empty claims map.
     *
     * @param subject The subject of the token (usually a username or user ID)
     * @return A JwtToken object containing the token string and its metadata
     */
    @Override
    public JwtToken generateToken(String subject) {
        return generateToken(subject, new HashMap<>());
    }

    /**
     * Validates a JWT token and returns its claims if valid.
     * <p>
     * This method performs the following validations:
     * <ol>
     *   <li>Checks if the token is blacklisted</li>
     *   <li>Verifies the token's signature</li>
     *   <li>Checks if the token has expired</li>
     *   <li>Extracts the token's claims and metadata</li>
     * </ol>
     * 
     * <p>
     * If the token is valid, returns a JwtToken object with the token's information.
     *
     * @param token The JWT token string to validate
     * @return A JwtToken object containing the token and its metadata
     * @throws JwtException If the token is invalid, malformed, or has been blacklisted
     * @throws TokenExpiredException If the token has expired
     */
    @Override
    public JwtToken validateToken(String token) throws JwtException, TokenExpiredException {
        if (tokenBlacklistService.isBlacklisted(token)) {
            throw new JwtException("Invalid JWT token: JWT token has been revoked");
        }

        Claims claims = extractAllClaims(token);
        String subject = claims.getSubject();
        Date issuedAt = claims.getIssuedAt();
        Date expiration = claims.getExpiration();

        if (isTokenExpired(token)) {
            throw new TokenExpiredException("JWT token is expired");
        }

        Map<String, Object> claimsMap = new HashMap<>(claims);

        return new JwtToken(token, subject, issuedAt, expiration, claimsMap);
    }
    
    /**
     * Invalidates a token by adding it to the blacklist.
     * <p>
     * Once a token is invalidated, it can no longer be used for authentication
     * even if it hasn't expired yet.
     * 
     * <p>
     * This method extracts the token's expiration time and adds it to the
     * blacklist with that expiration time.
     *
     * @param token The token to invalidate
     */
    @Override
    public void invalidateToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            Date expiration = claims.getExpiration();
            tokenBlacklistService.blacklistToken(token, expiration.getTime());
        } catch (Exception e) {
            logger.warn("Failed to invalidate token: {}", e.getMessage());
        }
    }

    /**
     * Refreshes an existing token, extending its expiration time.
     * <p>
     * This method creates a new token with the same subject and claims as the
     * original token, but with a new expiration date. It handles two scenarios:
     * <ol>
     *   <li>If the token is still valid, it creates a new token with the same claims</li>
     *   <li>If the token is expired but within the refresh window, it still allows refreshing</li>
     * </ol>
     * 
     * <p>
     * The refresh window is configured via the {@code jwt.refreshWindowMs} property
     * and defines a grace period after expiration during which tokens can still be refreshed.
     *
     * @param token The JWT token string to refresh
     * @return A new JwtToken object with extended expiration
     * @throws JwtException If the token is invalid, malformed, or has been blacklisted
     * @throws TokenExpiredException If the token is expired beyond the refresh window
     */
    @Override
    public JwtToken refreshToken(String token) throws JwtException {
        try {
            JwtToken validToken = validateToken(token);
            this.invalidateToken(validToken.getToken());
            return generateToken(validToken.getSubject(), validToken.getClaims());
        } catch (TokenExpiredException e) {
            Claims claims;
            try {
                claims = Jwts.parser()
                        .verifyWith(key)
                        .clockSkewSeconds(jwtProperties.getRefreshWindowMs())
                        .build()
                        .parseSignedClaims(token)
                        .getPayload();
            } catch (Exception ex) {
                throw new JwtException("Cannot refresh invalid token", ex);
            }

            Date expiration = claims.getExpiration();
            Date now = new Date();
            
            // Use the refresh window from properties
            if (now.getTime() - expiration.getTime() <= jwtProperties.getRefreshWindowMs()) {
                return generateToken(claims.getSubject(), new HashMap<>(claims));
            }
            
            throw new JwtException("Token expired beyond refresh window", e);
        }
    }

    /**
     * Extracts the subject from a JWT token without full validation.
     * <p>
     * This method extracts and returns the subject claim from the token
     * without performing full token validation.
     * 
     * <p>
     * Note that this method does not verify if the token is expired or blacklisted.
     * It only extracts the subject from the token's payload after verifying the signature.
     *
     * @param token The JWT token string
     * @return The subject of the token
     * @throws JwtException If the token is malformed or the subject cannot be extracted
     */
    @Override
    public String getSubjectFromToken(String token) {
        return extractAllClaims(token).getSubject();
    }

    /**
     * Checks if a JWT token is expired.
     * <p>
     * Determines if the token's expiration date has passed by comparing
     * the token's expiration date with the current date.
     *
     * @param token The JWT token string
     * @return true if the token is expired, false otherwise
     * @throws JwtException If the token is malformed or the expiration date cannot be extracted
     */
    @Override
    public boolean isTokenExpired(String token) {
        Date expirationDate;
        try{
            expirationDate = extractAllClaims(token).getExpiration();
        } catch (TokenExpiredException ignored) {
            return true;
        }

        return expirationDate.before(new Date());
    }

    /**
     * Extracts all claims from a JWT token.
     * <p>
     * This is a helper method that parses the token, verifies its signature,
     * and extracts all claims from the payload.
     * 
     * <p>
     * The method uses the configured secret key to verify the token's signature
     * before extracting the claims.
     *
     * @param token The JWT token string
     * @return The claims from the token
     * @throws TokenExpiredException If the token has expired
     * @throws JwtException If the token is malformed or the signature is invalid
     */
    private Claims extractAllClaims(String token) {
        try{
            return Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException exception) {
            throw new TokenExpiredException("Expired JWT token", exception);
        } catch (UnsupportedJwtException | IllegalArgumentException exception) {
            throw new JwtException("Invalid JWT token", exception);
        }
    }
}