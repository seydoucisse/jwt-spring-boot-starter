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

/**
 * Service interface for managing blacklisted JWT tokens.
 * <p>
 * This service provides functionality to blacklist JWT tokens that should no longer
 * be considered valid, even if they haven't expired yet. This is typically used for
 * implementing logout functionality, handling security breaches, or revoking access
 * for specific users.
 * 
 * <p>
 * The blacklist is typically implemented as a temporary storage that keeps tokens
 * only until their original expiration time. This prevents the blacklist from growing
 * indefinitely while still ensuring that revoked tokens cannot be used.
 * 
 * <p>
 * Implementations of this interface should consider:
 * <ul>
 *   <li>Performance implications of token lookup during validation</li>
 *   <li>Storage requirements for blacklisted tokens</li>
 *   <li>Cleanup mechanisms to remove expired tokens from the blacklist</li>
 *   <li>Persistence across application restarts (if required)</li>
 * </ul>
 * 
 * @author Seydou CISSE
 * @since 0.1.0
 * @see dev.scisse.jwt.service.JwtTokenService#invalidateToken(String)
 * @see dev.scisse.jwt.service.impl.InMemoryTokenBlacklistService
 */
public interface TokenBlacklistService {
    
    /**
     * Add a token to the blacklist.
     * <p>
     * Once a token is blacklisted, it should be considered invalid for authentication
     * purposes, even if it hasn't expired yet. The token will remain in the blacklist
     * until its original expiration time.
     * 
     * <p>
     * Implementations should ensure that blacklisted tokens are stored efficiently
     * and that expired tokens are eventually removed from the blacklist.
     *
     * @param token The JWT token string to blacklist
     * @param expirationTime The token's expiration time in milliseconds since epoch
     */
    void blacklistToken(String token, long expirationTime);
    
    /**
     * Check if a token is blacklisted.
     * <p>
     * This method is called during token validation to determine if a token
     * has been explicitly invalidated.
     * 
     * <p>
     * Implementations should optimize this method for performance, as it will be
     * called frequently during token validation.
     *
     * @param token The JWT token string to check
     * @return true if the token is blacklisted and should be considered invalid,
     *         false if the token is not blacklisted
     */
    boolean isBlacklisted(String token);
}