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
package dev.scisse.jwt.filter;

import dev.scisse.jwt.config.JwtProperties;
import dev.scisse.jwt.model.JwtToken;
import dev.scisse.jwt.service.JwtTokenService;
import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Filter for JWT authentication in Spring Security.
 * <p>
 * This filter intercepts HTTP requests and validates JWT tokens provided in the
 * request headers. It extracts the token, validates it using the {@link JwtTokenService},
 * and sets up the Spring Security authentication context based on the token's claims.
 * 
 * <p>
 * The filter supports:
 * <ul>
 *   <li>Configurable token extraction from request headers</li>
 *   <li>Path-based exclusion from JWT authentication</li>
 *   <li>Integration with Spring Security's {@link UserDetailsService} (required)</li>
 *   <li>Fallback to token-based authorities if user details are not found</li>
 * </ul>
 * 
 * <p>
 * <strong>Note:</strong> A {@link UserDetailsService} implementation must be provided
 * to use this filter. The filter will attempt to load user details from this service
 * when authenticating tokens, with a fallback to token-based authorities if the user
 * is not found.
 * 
 * <p>
 * The filter is automatically configured by the JWT starter when JWT authentication
 * is enabled, but can also be manually configured in a Spring Security setup.
 * 
 * 
 * @author Seydou CISSE
 * @since 0.1.0
 * @see dev.scisse.jwt.service.JwtTokenService
 * @see dev.scisse.jwt.config.JwtProperties
 * @see org.springframework.security.core.userdetails.UserDetailsService
 * @see org.springframework.web.filter.OncePerRequestFilter
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenService jwtTokenService;
    private final JwtProperties jwtProperties;
    private final UserDetailsService userDetailsService;
    private final RequestMatcher excludedPaths;

    /**
     * Constructs a new JwtAuthenticationFilter with the specified services and properties.
     * <p>
     * Initializes the filter with the necessary services for JWT validation and user details
     * loading. Also configures the request matcher for excluded paths based on the JWT properties.
     * 
     *
     * @param jwtTokenService   The service for validating and processing JWT tokens
     * @param jwtProperties     The configuration properties for JWT authentication
     * @param userDetailsService The service for loading user details by username (required)
     * @throws IllegalArgumentException if userDetailsService is null
     */
    public JwtAuthenticationFilter(JwtTokenService jwtTokenService, JwtProperties jwtProperties, UserDetailsService userDetailsService) {
        this.jwtTokenService = jwtTokenService;
        this.jwtProperties = jwtProperties;
        
        if (Objects.isNull(userDetailsService)) {
            throw new IllegalArgumentException("UserDetailsService is required for JWT authentication");
        }
        this.userDetailsService = userDetailsService;
        this.excludedPaths = new OrRequestMatcher(
                Arrays.stream(jwtProperties.getExcludedPaths())
                        .map(AntPathRequestMatcher::new)
                        .collect(Collectors.toList())
        );
    }

    /**
     * Determines whether the filter should not be applied to this request.
     * <p>
     * The filter will not be applied if:
     * <ul>
     *   <li>JWT authentication is disabled in the properties</li>
     *   <li>The request path matches one of the excluded paths</li>
     * </ul>
     * 
     *
     * @param request The HTTP request
     * @return true if the filter should not be applied, false otherwise
     */
    @Override
    protected boolean shouldNotFilter(@Nonnull HttpServletRequest request) {
        return !jwtProperties.isEnabled() || excludedPaths.matches(request);
    }

    /**
     * Processes the request for JWT authentication.
     * <p>
     * This method:
     * <ol>
     *   <li>Extracts the JWT token from the request</li>
     *   <li>Validates the token using the JWT token service</li>
     *   <li>Sets up the authentication context if the token is valid</li>
     *   <li>Continues the filter chain regardless of authentication result</li>
     * </ol>
     *
     * <p>
     * If token validation fails, the request continues without authentication.
     *
     *
     * @param request The HTTP request
     * @param response The HTTP response
     * @param filterChain The filter chain for continuing request processing
     * @throws ServletException If an error occurs during request processing
     * @throws IOException If an I/O error occurs during request processing
     */
    @Override
    protected void doFilterInternal(@Nonnull HttpServletRequest request, @Nonnull HttpServletResponse response, @Nonnull FilterChain filterChain)
            throws ServletException, IOException {

        String token = extractToken(request);

        if (Objects.nonNull(token)) {
            try {
                JwtToken jwtToken = jwtTokenService.validateToken(token);
                setAuthentication(request, jwtToken);
            } catch (Exception e) {
                // Token validation failed, continue without authentication
                logger.debug("JWT token validation failed: " + e.getMessage());
            }
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extracts the JWT token from the HTTP request.
     * <p>
     * Looks for the token in the request header specified by the JWT properties.
     * The token is expected to have a prefix (e.g., "Bearer ") which is removed
     * before returning the token.
     *
     * @param request The HTTP request
     * @return The JWT token string, or null if no token is found
     */
    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader(jwtProperties.getHeaderName());
        if (Objects.nonNull(header) && header.startsWith(jwtProperties.getTokenPrefix())) {
            return header.substring(jwtProperties.getTokenPrefix().length());
        }
        return null;
    }

    /**
     * Sets up the Spring Security authentication context based on the JWT token.
     * <p>
     * This method:
     * <ol>
     *   <li>Extracts the subject (username) from the token</li>
     *   <li>Attempts to load the user details from the UserDetailsService</li>
     *   <li>Creates an authentication token with the user details and authorities</li>
     *   <li>Sets the authentication in the SecurityContextHolder</li>
     * </ol>
     *
     * <p>
     * If the user is not found in the UserDetailsService, falls back to using
     * the authorities from the token's claims.
     *
     * @param jwtToken The validated JWT token
     */
    private void setAuthentication(HttpServletRequest request, JwtToken jwtToken) {
        String username = jwtToken.getSubject();
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}