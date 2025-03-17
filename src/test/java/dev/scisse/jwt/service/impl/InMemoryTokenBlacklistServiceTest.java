package dev.scisse.jwt.service.impl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InMemoryTokenBlacklistServiceTest {

    private InMemoryTokenBlacklistService tokenBlacklistService;

    @BeforeEach
    void setUp() {
        tokenBlacklistService = new InMemoryTokenBlacklistService();
    }

    @Test
    void shouldBlacklistToken() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test";
        long expirationTime = System.currentTimeMillis() + 3600000; // 1 hour from now

        tokenBlacklistService.blacklistToken(token, expirationTime);

        assertTrue(tokenBlacklistService.isBlacklisted(token));
    }

    @Test
    void shouldReturnFalseIfTokenNotInBlacklist() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.notExists";

        boolean result = tokenBlacklistService.isBlacklisted(token);

        assertFalse(result);
    }

    @Test
    void shouldNotBlacklistExpiredToken() {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.expired";

        long expirationTime = System.currentTimeMillis() - 1000;
        tokenBlacklistService.blacklistToken(token, expirationTime);

        assertFalse(tokenBlacklistService.isBlacklisted(token));
    }

    @Test
    void shouldCleanExpiredTokens() {
        String validToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.valid";
        String expiredToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.expired";
        long currentTime = System.currentTimeMillis();
        tokenBlacklistService.blacklistToken(validToken, currentTime + 3600000); // 1 hour from now
        tokenBlacklistService.blacklistToken(expiredToken, currentTime - 1000); // 1 second ago (expired)

        tokenBlacklistService.cleanupExpiredTokens();

        assertTrue(tokenBlacklistService.isBlacklisted(validToken));
        assertFalse(tokenBlacklistService.isBlacklisted(expiredToken));
    }

    @Test
    void shouldAddConcurrentlyTokens() throws InterruptedException {
        int threadCount = 10;
        Thread[] threads = new Thread[threadCount];
        
        // Create multiple threads that add tokens to the blacklist
        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                String token = "token" + index;
                long expiry = System.currentTimeMillis() + 3600000;
                tokenBlacklistService.blacklistToken(token, expiry);
            });
            threads[i].start();
        }

        for (Thread thread : threads) {
            thread.join();
        }
        
        // Then
        for (int i = 0; i < threadCount; i++) {
            assertTrue(tokenBlacklistService.isBlacklisted("token" + i));
        }
    }
}