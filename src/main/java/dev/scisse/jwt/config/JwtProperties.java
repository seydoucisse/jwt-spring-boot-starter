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
import org.springframework.boot.context.properties.bind.DefaultValue;

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
 *   excluded-paths: /api/auth/**, /public/**
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
public record JwtProperties(
    /*
     * Secret key used for signing JWT tokens.
     * <p>
     * This property is mandatory and must be specified in your configuration.
     * It should be a strong, unique secret that is kept secure.
     */
    String secret,
    
    /*
     * Token expiration time in milliseconds.
     * <p>
     * Specifies how long a generated token will be valid before it expires.
     * 
     * <p>
     * Default: 24 hours (86,400,000 milliseconds)
     */
    @DefaultValue("86400000")
    long expirationMs,

    /*
     * Refresh window time in milliseconds.
     * <p>
     * Defines the time window after token expiration during which the token
     * can still be refreshed. This allows for token refresh even if the token
     * has just expired.
     * 
     * <p>
     * Default: 5 minutes (300,000 milliseconds)
     */
    @DefaultValue("300000")
    long refreshWindowMs,

    /*
     * Interval for cleaning up blacklisted tokens in milliseconds.
     * <p>
     * Specifies how often the system should clean up expired tokens from the
     * blacklist.
     * 
     * <p>
     * Default: 10 minutes (600,000 milliseconds)
     */
    @DefaultValue("600000")
    long blacklistedCleanupIntervalMs,
    
    /*
     * Token issuer.
     * <p>
     * The issuer claim to include in JWT tokens. This helps identify the source
     * of the token.
     * 
     * <p>
     * This property is mandatory and must be specified in your configuration.
     */
    String issuer,
    
    /*
     * Paths to exclude from JWT authentication.
     * <p>
     * Specifies URL patterns that should be excluded from JWT authentication.
     * These paths will be accessible without a valid JWT token.
     * 
     * <p>
     * Default: ["/api/auth/**", "/swagger-ui/**", "/v3/api-docs/**"]
     */
    @DefaultValue({"/api/auth/**", "/swagger-ui/**", "/v3/api-docs/**"})
    String[] excludedPaths,
    
    /*
     * Whether to enable JWT authentication.
     * <p>
     * Controls whether JWT authentication is enabled for the application.
     * When set to false, JWT authentication will be disabled.
     * 
     * <p>
     * Default: true
     */
    @DefaultValue("true")
    boolean enabled,
    
    /*
     * Header name for the JWT token.
     * <p>
     * Specifies the HTTP header name where the JWT token should be provided
     * in requests.
     * 
     * <p>
     * Default: "Authorization"
     */
    @DefaultValue("Authorization")
    String headerName,

    /*
     * Token prefix in the Authorization header.
     * <p>
     * Specifies the prefix that should be used before the JWT token in the
     * authorization header. The token in the header should be formatted as:
     * "{tokenPrefix}{token}".
     *
     * <p>
     * Default: "Bearer "
     */
    @DefaultValue("Bearer ")
    String tokenPrefix
) {
    /**
     * Default constructor with default values for optional properties.
     * Required for Spring Boot property binding.
     */
    public JwtProperties {
        if (expirationMs == 0) {
            expirationMs = 24 * 60 * 60 * 1000L; // 24 hours
        }
        if (refreshWindowMs == 0) {
            refreshWindowMs = 5 * 60 * 1000L; // 5 minutes
        }
        if (blacklistedCleanupIntervalMs == 0) {
            blacklistedCleanupIntervalMs = 10 * 60 * 1000L; // 10 minutes
        }
        if (excludedPaths == null) {
            excludedPaths = new String[]{"/api/auth/**", "/swagger-ui/**", "/v3/api-docs/**"};
        }
        if (headerName == null) {
            headerName = "Authorization";
        }
        if (tokenPrefix == null) {
            tokenPrefix = "Bearer ";
        }
    }
}