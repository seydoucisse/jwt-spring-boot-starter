package dev.scisse.jwt.service.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;

import java.lang.reflect.Field;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

@ExtendWith(MockitoExtension.class)
public class InMemoryTokenBlacklistServiceTest {

    @Mock
    private Logger logger;

    @InjectMocks
    private InMemoryTokenBlacklistService tokenBlacklistService;

    private Map<String, Long> blacklistedTokens;

    @BeforeEach
    public void setUp() throws Exception {
        // Access the private blacklistedTokens field for testing
        blacklistedTokens = new ConcurrentHashMap<>();
        Field blacklistedTokensField = InMemoryTokenBlacklistService.class.getDeclaredField("blacklistedTokens");
        blacklistedTokensField.setAccessible(true);
        blacklistedTokensField.set(tokenBlacklistService, blacklistedTokens);
    }

    @Test
    public void testBlacklistToken() {
        // Given
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test";
        long expirationTime = System.currentTimeMillis() + 3600000; // 1 hour from now

        // When
        tokenBlacklistService.blacklistToken(token, expirationTime);

        // Then
        assertTrue(blacklistedTokens.containsKey(token));
        assertEquals(expirationTime, blacklistedTokens.get(token));
        verify(logger).debug(contains("Token blacklisted"), eq(token));
    }

    @Test
    public void testIsBlacklisted_TokenExists() {
        // Given
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.exists";
        blacklistedTokens.put(token, System.currentTimeMillis() + 3600000);

        // When
        boolean result = tokenBlacklistService.isBlacklisted(token);

        // Then
        assertTrue(result);
    }

    @Test
    public void testIsBlacklisted_TokenDoesNotExist() {
        // Given
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.notExists";

        // When
        boolean result = tokenBlacklistService.isBlacklisted(token);

        // Then
        assertFalse(result);
    }

    @Test
    public void testCleanupExpiredTokens() {
        // Given
        String validToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.valid";
        String expiredToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.expired";
        
        long currentTime = System.currentTimeMillis();
        blacklistedTokens.put(validToken, currentTime + 3600000); // 1 hour from now
        blacklistedTokens.put(expiredToken, currentTime - 1000); // 1 second ago (expired)

        // When
        tokenBlacklistService.cleanupExpiredTokens();

        // Then
        assertTrue(blacklistedTokens.containsKey(validToken));
        assertFalse(blacklistedTokens.containsKey(expiredToken));
        verify(logger).debug(contains("Cleaning up expired blacklisted tokens"));
        verify(logger).debug(contains("Blacklist cleanup completed"), anyInt());
    }

    @Test
    public void testConcurrentAccess() throws InterruptedException {
        // Given
        int threadCount = 10;
        Thread[] threads = new Thread[threadCount];
        
        // When - create multiple threads that add tokens to the blacklist
        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                String token = "token" + index;
                long expiry = System.currentTimeMillis() + 3600000;
                tokenBlacklistService.blacklistToken(token, expiry);
            });
            threads[i].start();
        }
        
        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join();
        }
        
        // Then
        assertEquals(threadCount, blacklistedTokens.size());
        for (int i = 0; i < threadCount; i++) {
            assertTrue(blacklistedTokens.containsKey("token" + i));
        }
    }
}