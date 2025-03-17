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

import dev.scisse.jwt.service.TokenBlacklistService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Primary;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of the TokenBlacklistService.
 * <p>
 * This implementation stores blacklisted tokens in a thread-safe ConcurrentHashMap
 * and periodically cleans up expired tokens to prevent memory leaks. It provides
 * a simple and efficient way to invalidate JWT tokens without requiring external
 * storage or persistence.
 *
 * <p>
 * Key features:
 * <ul>
 *   <li>Thread-safe implementation using ConcurrentHashMap</li>
 *   <li>Automatic cleanup of expired tokens via scheduled task</li>
 *   <li>Efficient token lookup during validation</li>
 *   <li>Low memory footprint for typical usage patterns</li>
 * </ul>
 *
 * <p>
 * Limitations :
 * <ul>
 *   <li>Tokens are not persisted across application restarts</li>
 *   <li>Not suitable for distributed environments without additional synchronization</li>
 *   <li>Memory usage scales with the number of blacklisted tokens</li>
 * </ul>
 *
 * <p>
 * This is a fallback implementation that will only be used if no other
 * TokenBlacklistService bean is provided by the user. Applications requiring
 * persistence or distributed token blacklisting should provide their own
 * implementation of the TokenBlacklistService interface.
 * 
 * @author Seydou CISSE
 * @since 0.1.0
 * @see dev.scisse.jwt.service.TokenBlacklistService
 * @see org.springframework.scheduling.annotation.Scheduled
 */
@Service
@ConditionalOnMissingBean(TokenBlacklistService.class)
@Primary
public class InMemoryTokenBlacklistService implements TokenBlacklistService {
    
    private static final Logger logger = LoggerFactory.getLogger(InMemoryTokenBlacklistService.class);
    
    /**
     * Map to store blacklisted tokens with their expiration times.
     * <p>
     * The key is the token string, and the value is the expiration time in milliseconds
     * since epoch. ConcurrentHashMap is used to ensure thread safety for concurrent
     * access from multiple requests.
     */
    private final Map<String, Long> blacklistedTokens = new ConcurrentHashMap<>();
    
    /**
     * Adds a token to the blacklist.
     * <p>
     * The token will remain in the blacklist until its original expiration time
     * or until it is removed by the cleanup task.
     *
     * @param token The JWT token string to blacklist
     * @param expirationTime The token's expiration time in milliseconds since epoch
     */
    @Override
    public void blacklistToken(String token, long expirationTime) {
        logger.debug("Blacklisting token with expiration: {}", new Date(expirationTime));
        blacklistedTokens.put(token, expirationTime);
    }
    
    /**
     * Checks if a token is blacklisted.
     * <p>
     * This method also performs cleanup of expired tokens when they are accessed,
     * which helps to keep the blacklist size manageable between scheduled cleanups.
     * <p>
     * The method follows these steps:
     * <ol>
     *   <li>Check if the token exists in the blacklist</li>
     *   <li>If found, check if it has expired</li>
     *   <li>If expired, remove it from the blacklist and return false</li>
     *   <li>If not expired, return true (token is blacklisted)</li>
     * </ol>
     *
     * @param token The JWT token string to check
     * @return true if the token is blacklisted and not expired, false otherwise
     */
    @Override
    public boolean isBlacklisted(String token) {
        if (!blacklistedTokens.containsKey(token)) {
            return false;
        }

        long expirationTime = blacklistedTokens.get(token);
        long currentTime = System.currentTimeMillis();

        if (currentTime > expirationTime) {
            blacklistedTokens.remove(token);
            return false;
        }
        
        return true;
    }
    
    /**
     * Scheduled task to clean up expired tokens from the blacklist.
     * <p>
     * This method periodically removes all expired tokens from the blacklist
     * to prevent memory leaks. The cleanup interval is configured via the
     * {@code jwt.blacklistedCleanupIntervalMs} property.
     *
     * <p>
     * The cleanup process:
     * <ol>
     *   <li>Gets the current time</li>
     *   <li>Iterates through all entries in the blacklist</li>
     *   <li>Removes entries where the expiration time is before the current time</li>
     *   <li>Logs the number of remaining tokens after cleanup</li>
     * </ol>
     *
     */
    @Scheduled(fixedRateString = "${jwt.blacklisted-cleanup-interval-ms}")
    public void cleanupExpiredTokens() {
        logger.debug("Cleaning up expired blacklisted tokens");
        long currentTime = System.currentTimeMillis();
        
        blacklistedTokens.entrySet().removeIf(entry -> currentTime > entry.getValue());
        
        logger.debug("Blacklist cleanup completed. Remaining tokens: {}", blacklistedTokens.size());
    }
}