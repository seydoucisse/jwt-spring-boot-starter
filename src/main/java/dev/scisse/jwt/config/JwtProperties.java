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
package dev.scisse.jwt.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for JWT authentication.
 * <p>
 * This class defines the configuration properties for JWT authentication,
 * including token generation, validation, and filter behavior. These properties
 * can be configured in application.properties or application.yml using the
 * 'jwt' prefix.
 * 
 * <p>
 * Example configuration in application.yml:
 * 
 * <pre>
 * jwt:
 *   secret: your-secret-key
 *   issuer: your-application
 *   expiration-ms: 86400000
 *   refresh-window-ms: 300000
 *   excludedPaths: /api/auth/**, /public/**
 *   enabled: true
 *   header-name: Authorization
 *   token-prefix: "Bearer "
 * </pre>
 * <p>
 * Required properties:
 * 
 * <ul>
 *   <li>secret - The secret key used for signing JWT tokens</li>
 *   <li>issuer - The issuer claim to include in JWT tokens</li>
 * </ul>
 * 
 * @author Seydou CISSE
 * @since 0.1.0
 * @see dev.scisse.jwt.autoconfigure.JwtAutoConfiguration
 */
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    
    /**
     * Secret key used for signing JWT tokens.
     * <p>
     * This property is mandatory and must be specified in your configuration.
     * It should be a strong, unique secret that is kept secure.
     * 
     */
    private String secret;
    
    /**
     * Token expiration time in milliseconds.
     * <p>
     * Specifies how long a generated token will be valid before it expires.
     * 
     * <p>
     * Default: 24 hours (86,400,000 milliseconds)
     * 
     */
    private long expirationMs = 24 * 60 * 60 * 1000L;

    /**
     * Refresh window time in milliseconds.
     * <p>
     * Defines the time window after token expiration during which the token
     * can still be refreshed. This allows for token refresh even if the token
     * has just expired.
     * 
     * <p>
     * Default: 5 minutes (300,000 milliseconds)
     * 
     */
    private long refreshWindowMs = 5 * 60 * 1000L;

    /**
     * Interval for cleaning up blacklisted tokens in milliseconds.
     * <p>
     * Specifies how often the system should clean up expired tokens from the
     * blacklist.
     * 
     * <p>
     * Default: 10 minutes (600,000 milliseconds)
     * 
     */
    private long blacklistedCleanupIntervalMs = 10 * 60 * 1000L;
    
    /**
     * Token issuer.
     * <p>
     * The issuer claim to include in JWT tokens. This helps identify the source
     * of the token.
     * 
     * <p>
     * This property is mandatory and must be specified in your configuration.
     * 
     */
    private String issuer;
    
    /**
     * Paths to exclude from JWT authentication.
     * <p>
     * Specifies URL patterns that should be excluded from JWT authentication.
     * These paths will be accessible without a valid JWT token.
     * 
     * <p>
     * Default: ["/api/auth/**", "/swagger-ui/**", "/v3/api-docs/**"]
     * 
     */
    private String[] excludedPaths = {"/api/auth/**", "/swagger-ui/**", "/v3/api-docs/**"};
    
    /**
     * Whether to enable JWT authentication.
     * <p>
     * Controls whether JWT authentication is enabled for the application.
     * When set to false, JWT authentication will be disabled.
     * 
     * <p>
     * Default: true
     */
    private boolean enabled = true;
    
    /**
     * Header name for the JWT token.
     * <p>
     * Specifies the HTTP header name where the JWT token should be provided
     * in requests.
     * 
     * <p>
     * Default: "Authorization"
     */
    private String headerName = "Authorization";
    
    /**
     * Token prefix in the Authorization header.
     * <p>
     * Specifies the prefix that should be used before the JWT token in the
     * authorization header. The token in the header should be formatted as:
     * "{tokenPrefix}{token}".
     * 
     * <p>
     * Default: "Bearer "
     */
    private String tokenPrefix = "Bearer ";

    /**
     * Gets the secret key used for signing JWT tokens.
     *
     * @return The secret key
     */
    public String getSecret() {
        return secret;
    }

    /**
     * Sets the secret key used for signing JWT tokens.
     *
     * @param secret The secret key to set
     */
    public void setSecret(String secret) {
        this.secret = secret;
    }

    /**
     * Gets the token expiration time in milliseconds.
     *
     * @return The token expiration time in milliseconds
     */
    public long getExpirationMs() {
        return expirationMs;
    }

    /**
     * Sets the token expiration time in milliseconds.
     *
     * @param expirationMs The token expiration time to set
     */
    public void setExpirationMs(long expirationMs) {
        this.expirationMs = expirationMs;
    }

    /**
     * Gets the refresh window time in milliseconds.
     *
     * @return The refresh window time in milliseconds
     */
    public long getRefreshWindowMs() {
        return refreshWindowMs;
    }

    /**
     * Sets the refresh window time in milliseconds.
     *
     * @param refreshWindowMs The refresh window time to set
     */
    public void setRefreshWindowMs(long refreshWindowMs) {
        this.refreshWindowMs = refreshWindowMs;
    }

    /**
     * Gets the interval for cleaning up blacklisted tokens in milliseconds.
     *
     * @return The cleanup interval in milliseconds
     */
    public long getBlacklistedCleanupIntervalMs() {
        return blacklistedCleanupIntervalMs;
    }

    /**
     * Sets the interval for cleaning up blacklisted tokens in milliseconds.
     *
     * @param cleanupIntervalMs The cleanup interval to set
     */
    public void setBlacklistedCleanupIntervalMs(long cleanupIntervalMs) {
        this.blacklistedCleanupIntervalMs = cleanupIntervalMs;
    }

    /**
     * Gets the token issuer.
     *
     * @return The token issuer
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Sets the token issuer.
     *
     * @param issuer The token issuer to set
     */
    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    /**
     * Gets the paths to exclude from JWT authentication.
     *
     * @return The excluded paths
     */
    public String[] getExcludedPaths() {
        return excludedPaths;
    }

    /**
     * Sets the paths to exclude from JWT authentication.
     *
     * @param excludedPaths The excluded paths to set
     */
    public void setExcludedPaths(String[] excludedPaths) {
        this.excludedPaths = excludedPaths;
    }

    /**
     * Checks if JWT authentication is enabled.
     *
     * @return true if JWT authentication is enabled, false otherwise
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether JWT authentication is enabled.
     *
     * @param enabled true to enable JWT authentication, false to disable
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Gets the header name for the JWT token.
     *
     * @return The header name
     */
    public String getHeaderName() {
        return headerName;
    }

    /**
     * Sets the header name for the JWT token.
     *
     * @param headerName The header name to set
     */
    public void setHeaderName(String headerName) {
        this.headerName = headerName;
    }

    /**
     * Gets the token prefix in the Authorization header.
     *
     * @return The token prefix
     */
    public String getTokenPrefix() {
        return tokenPrefix;
    }

    /**
     * Sets the token prefix in the Authorization header.
     *
     * @param tokenPrefix The token prefix to set
     */
    public void setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix;
    }
}