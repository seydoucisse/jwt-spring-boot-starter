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
package dev.scisse.jwt.service;

import java.util.Map;

import dev.scisse.jwt.exception.JwtException;
import dev.scisse.jwt.exception.TokenExpiredException;
import dev.scisse.jwt.model.JwtToken;

/**
 * Service interface for JWT token operations.
 * <p>
 * This interface defines the contract for JWT token generation, validation,
 * and information extraction operations. Implementations of this interface
 * handle the creation of JWT tokens with claims, validation of tokens,
 * and extraction of information from tokens.
 * </p>
 * <p>
 * The service provides methods to:
 * <ul>
 *   <li>Generate JWT tokens with custom claims</li>
 *   <li>Validate existing tokens</li>
 *   <li>Extract information from tokens</li>
 *   <li>Refresh tokens to extend their validity</li>
 *   <li>Invalidate tokens by adding them to a blacklist</li>
 * </ul>
 * </p>
 * <p>
 * This service is a core component of the JWT authentication system and is typically
 * used by authentication filters, controllers, and other security-related components.
 * </p>
 *
 * @author Seydou CISSE
 * @since 0.1.0
 * @see dev.scisse.jwt.model.JwtToken
 * @see dev.scisse.jwt.service.TokenBlacklistService
 * @see dev.scisse.jwt.exception.JwtException
 * @see dev.scisse.jwt.exception.TokenExpiredException
 */
public interface JwtTokenService {
    
    /**
     * Generate a JWT token for the given subject and claims.
     * <p>
     * Creates a new JWT token with the specified subject and additional claims.
     * The token will include standard claims like issuedAt and expiration based
     * on the configuration.
     * </p>
     * <p>
     * The generated token includes:
     * <ul>
     *   <li>The provided subject (typically a username or user ID)</li>
     *   <li>The provided custom claims</li>
     *   <li>Standard claims like issuedAt, expiration, and issuer</li>
     *   <li>A digital signature created using the configured secret key</li>
     * </ul>
     * </p>
     *
     * @param subject The subject of the token (usually a username or user ID)
     * @param claims Additional claims to include in the token
     * @return A JwtToken object containing the token string and its metadata
     * @see dev.scisse.jwt.model.JwtToken
     */
    JwtToken generateToken(String subject, Map<String, Object> claims);
    
    /**
     * Generate a JWT token for the given subject without additional claims.
     * <p>
     * Creates a new JWT token with only the specified subject and standard claims
     * like issuedAt and expiration based on the configuration.
     * </p>
     * <p>
     * This is a convenience method that calls {@link #generateToken(String, Map)}
     * with an empty claims map.
     * </p>
     *
     * @param subject The subject of the token (usually a username or user ID)
     * @return A JwtToken object containing the token string and its metadata
     * @see #generateToken(String, Map)
     */
    JwtToken generateToken(String subject);
    
    /**
     * Validate a JWT token and return its claims if valid.
     * <p>
     * Validates the token's signature, expiration, and other criteria.
     * If the token is valid, returns a JwtToken object with the token's information.
     * </p>
     * <p>
     * The validation process includes:
     * <ul>
     *   <li>Checking if the token is blacklisted</li>
     *   <li>Verifying the token's digital signature</li>
     *   <li>Checking if the token has expired</li>
     *   <li>Extracting the token's claims and metadata</li>
     * </ul>
     * </p>
     *
     * @param token The JWT token string to validate
     * @return A JwtToken object containing the token and its metadata
     * @throws JwtException If the token is invalid, malformed, or has been blacklisted
     * @throws TokenExpiredException If the token has expired
     * @see dev.scisse.jwt.model.JwtToken
     * @see dev.scisse.jwt.exception.JwtException
     * @see dev.scisse.jwt.exception.TokenExpiredException
     */
    JwtToken validateToken(String token) throws JwtException;
    
    /**
     * Extract the subject from a JWT token without full validation.
     * <p>
     * This method extracts and returns the subject claim from the token
     * without performing full token validation.
     * </p>
     * <p>
     * Note that this method does not verify if the token is expired or blacklisted.
     * It only extracts the subject from the token's payload.
     * </p>
     *
     * @param token The JWT token string
     * @return The subject of the token
     * @throws JwtException If the token is malformed or the subject cannot be extracted
     */
    String getSubjectFromToken(String token);
    
    /**
     * Check if a JWT token is expired.
     * <p>
     * Determines if the token's expiration date has passed.
     * </p>
     * <p>
     * This method compares the token's expiration date with the current date
     * to determine if the token has expired.
     * </p>
     *
     * @param token The JWT token string
     * @return true if the token is expired, false otherwise
     * @throws JwtException If the token is malformed or the expiration date cannot be extracted
     */
    boolean isTokenExpired(String token);
    
    /**
     * Refresh an existing token, extending its expiration time.
     * <p>
     * Creates a new token with the same subject and claims as the original token,
     * but with a new expiration date. The original token may be invalidated depending
     * on the implementation.
     * </p>
     * <p>
     * This method can handle two scenarios:
     * <ul>
     *   <li>If the token is still valid, it creates a new token with the same claims</li>
     *   <li>If the token is expired but within the refresh window, it still allows refreshing</li>
     * </ul>
     * </p>
     *
     * @param token The JWT token string to refresh
     * @return A new JwtToken object with extended expiration
     * @throws JwtException If the token is invalid, malformed, or has been blacklisted
     * @throws TokenExpiredException If the token is expired beyond the refresh window
     * @see dev.scisse.jwt.model.JwtToken
     * @see dev.scisse.jwt.exception.JwtException
     * @see dev.scisse.jwt.exception.TokenExpiredException
     */
    JwtToken refreshToken(String token) throws JwtException;
    
    /**
     * Invalidate a token by adding it to the blacklist.
     * <p>
     * Once a token is invalidated, it can no longer be used for authentication
     * even if it hasn't expired yet.
     * </p>
     * <p>
     * This method is typically used for logout operations or when a security
     * breach is detected.
     * </p>
     *
     * @param token The token to invalidate
     * @see dev.scisse.jwt.service.TokenBlacklistService
     */
    void invalidateToken(String token);
}